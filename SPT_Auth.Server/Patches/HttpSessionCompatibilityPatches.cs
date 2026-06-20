using System.Collections.Concurrent;
using HarmonyLib;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Servers;

namespace SPT_Auth.Server.Patches;

/// <summary>
/// Keeps the SPT session cookie usable when a reverse proxy applies stricter
/// cookie path handling or drops the cookie on selected SPT/Fika routes.
/// </summary>
[HarmonyPatch(typeof(HttpServer), nameof(HttpServer.HandleRequest))]
public static class HttpSessionCompatibilityPatches
{
    private const string SessionCookieName = "PHPSESSID";
    private const string GameConfigPath = "/client/game/config";
    private const string FikaPathPrefix = "/fika";
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(10);
    private static readonly ConcurrentDictionary<string, ConcurrentDictionary<MongoId, DateTimeOffset>> SessionsByClient = new();

    [HarmonyPrefix]
    public static void Prefix(HttpContext context)
    {
        context.Response.OnStarting(NormalizeSessionCookie, context.Response);

        var clientKey = GetClientKey(context);
        if (TryGetSessionId(context.Request.Headers.Cookie, out var sessionId))
        {
            var observedSessions = SessionsByClient.GetOrAdd(clientKey, static _ => new());
            observedSessions[sessionId] = DateTimeOffset.UtcNow;
            RemoveExpiredSessions();
            return;
        }

        if (
            !IsSessionRecoveryPath(context.Request.Path)
            || !SessionsByClient.TryGetValue(clientKey, out var clientSessions)
        )
        {
            return;
        }

        RemoveExpiredSessions(clientKey, clientSessions);

        // Reverse proxies can make multiple players share the same apparent IP
        // and Fika clients commonly use the same User-Agent. Recovering the most
        // recently seen session in that case would silently impersonate another
        // player. Only recover when the client key identifies one active session.
        var candidates = clientSessions.ToArray();
        if (candidates.Length != 1)
        {
            return;
        }

        var (cachedSessionId, _) = candidates[0];

        // HttpServer has not read Request.Cookies yet, so updating the raw
        // header here makes the recovered value visible to the original code.
        var existingCookies = context.Request.Headers.Cookie.ToString();
        context.Request.Headers.Cookie = string.IsNullOrWhiteSpace(existingCookies)
            ? $"{SessionCookieName}={cachedSessionId}"
            : $"{existingCookies}; {SessionCookieName}={cachedSessionId}";

        clientSessions[cachedSessionId] = DateTimeOffset.UtcNow;
    }

    private static Task NormalizeSessionCookie(object state)
    {
        var response = (HttpResponse)state;
        if (!response.Headers.TryGetValue("Set-Cookie", out var setCookieHeaders))
        {
            return Task.CompletedTask;
        }

        var normalizedHeaders = new List<string>(setCookieHeaders.Count);
        foreach (var header in setCookieHeaders)
        {
            if (header is null || !header.StartsWith($"{SessionCookieName}=", StringComparison.OrdinalIgnoreCase))
            {
                if (header is not null)
                {
                    normalizedHeaders.Add(header);
                }

                continue;
            }

            var cookieValue = header.Split(';', 2)[0][($"{SessionCookieName}=").Length..];

            // An unauthenticated request must not erase a valid client cookie.
            if (string.IsNullOrWhiteSpace(cookieValue))
            {
                continue;
            }

            normalizedHeaders.Add(NormalizeCookiePath(header));
        }

        if (normalizedHeaders.Count == 0)
        {
            response.Headers.Remove("Set-Cookie");
        }
        else
        {
            response.Headers["Set-Cookie"] = new StringValues(normalizedHeaders.ToArray());
        }

        return Task.CompletedTask;
    }

    private static bool IsSessionRecoveryPath(PathString path)
    {
        if (path.Equals(GameConfigPath, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var value = path.Value;
        return value is not null
            && (
                value.Equals(FikaPathPrefix, StringComparison.OrdinalIgnoreCase)
                || value.StartsWith($"{FikaPathPrefix}/", StringComparison.OrdinalIgnoreCase)
            );
    }

    private static string NormalizeCookiePath(string header)
    {
        var attributes = header.Split(';', StringSplitOptions.TrimEntries);
        var normalized = new List<string>(attributes.Length + 1) { attributes[0] };
        var pathWritten = false;

        foreach (var attribute in attributes.Skip(1))
        {
            if (attribute.StartsWith("Path=", StringComparison.OrdinalIgnoreCase))
            {
                if (!pathWritten)
                {
                    normalized.Add("Path=/");
                    pathWritten = true;
                }

                continue;
            }

            if (!string.IsNullOrWhiteSpace(attribute))
            {
                normalized.Add(attribute);
            }
        }

        if (!pathWritten)
        {
            normalized.Add("Path=/");
        }

        return string.Join("; ", normalized);
    }

    private static bool TryGetSessionId(StringValues cookieHeaders, out MongoId sessionId)
    {
        foreach (var cookieHeader in cookieHeaders)
        {
            if (cookieHeader is null)
            {
                continue;
            }

            foreach (var cookie in cookieHeader.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var separatorIndex = cookie.IndexOf('=');
                if (separatorIndex <= 0 || !cookie[..separatorIndex].Equals(SessionCookieName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var value = cookie[(separatorIndex + 1)..].Trim();
                if (MongoId.IsValidMongoId(value))
                {
                    sessionId = new MongoId(value);
                    return !sessionId.IsEmpty;
                }
            }
        }

        sessionId = MongoId.Empty();
        return false;
    }

    private static string GetClientKey(HttpContext context)
    {
        var clientAddress = GetFirstHeaderValue(context, "X-Forwarded-For")
            ?? GetFirstHeaderValue(context, "X-Real-IP")
            ?? GetFirstHeaderValue(context, "CF-Connecting-IP")
            ?? context.Connection.RemoteIpAddress?.ToString()
            ?? "unknown";

        return $"{clientAddress}|{context.Request.Headers.UserAgent}";
    }

    private static string? GetFirstHeaderValue(HttpContext context, string headerName)
    {
        if (!context.Request.Headers.TryGetValue(headerName, out var values))
        {
            return null;
        }

        return values
            .SelectMany(value => value?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? [])
            .FirstOrDefault();
    }

    private static void RemoveExpiredSessions()
    {
        var expiry = DateTimeOffset.UtcNow - SessionLifetime;
        foreach (var (clientKey, clientSessions) in SessionsByClient)
        {
            RemoveExpiredSessions(clientKey, clientSessions, expiry);
        }
    }

    private static void RemoveExpiredSessions(
        string clientKey,
        ConcurrentDictionary<MongoId, DateTimeOffset> clientSessions
    )
    {
        RemoveExpiredSessions(clientKey, clientSessions, DateTimeOffset.UtcNow - SessionLifetime);
    }

    private static void RemoveExpiredSessions(
        string clientKey,
        ConcurrentDictionary<MongoId, DateTimeOffset> clientSessions,
        DateTimeOffset expiry
    )
    {
        foreach (var (sessionId, lastSeen) in clientSessions)
        {
            if (lastSeen < expiry)
            {
                clientSessions.TryRemove(sessionId, out _);
            }
        }

        if (clientSessions.IsEmpty)
        {
            SessionsByClient.TryRemove(
                new KeyValuePair<string, ConcurrentDictionary<MongoId, DateTimeOffset>>(clientKey, clientSessions)
            );
        }
    }
}
