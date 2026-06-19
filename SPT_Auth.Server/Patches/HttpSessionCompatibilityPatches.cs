using System.Collections.Concurrent;
using HarmonyLib;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Servers;

namespace SPT_Auth.Server.Patches;

/// <summary>
/// Keeps the SPT session cookie usable when a reverse proxy applies stricter
/// cookie path handling or drops the cookie on /client/game/config.
/// </summary>
[HarmonyPatch(typeof(HttpServer), nameof(HttpServer.HandleRequest))]
public static class HttpSessionCompatibilityPatches
{
    private const string SessionCookieName = "PHPSESSID";
    private const string GameConfigPath = "/client/game/config";
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(10);
    private static readonly ConcurrentDictionary<string, CachedSession> SessionsByClient = new();

    [HarmonyPrefix]
    public static void Prefix(HttpContext context)
    {
        context.Response.OnStarting(NormalizeSessionCookie, context.Response);

        var clientKey = GetClientKey(context);
        if (TryGetSessionId(context.Request.Headers.Cookie, out var sessionId))
        {
            SessionsByClient[clientKey] = new CachedSession(sessionId, DateTimeOffset.UtcNow);
            RemoveExpiredSessions();
            return;
        }

        if (
            !context.Request.Path.Equals(GameConfigPath, StringComparison.OrdinalIgnoreCase)
            || !SessionsByClient.TryGetValue(clientKey, out var cachedSession)
        )
        {
            return;
        }

        if (DateTimeOffset.UtcNow - cachedSession.LastSeen > SessionLifetime)
        {
            SessionsByClient.TryRemove(clientKey, out _);
            return;
        }

        // HttpServer has not read Request.Cookies yet, so updating the raw
        // header here makes the recovered value visible to the original code.
        var existingCookies = context.Request.Headers.Cookie.ToString();
        context.Request.Headers.Cookie = string.IsNullOrWhiteSpace(existingCookies)
            ? $"{SessionCookieName}={cachedSession.SessionId}"
            : $"{existingCookies}; {SessionCookieName}={cachedSession.SessionId}";

        SessionsByClient[clientKey] = cachedSession with { LastSeen = DateTimeOffset.UtcNow };
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

            normalizedHeaders.Add(
                header.Contains("Path=", StringComparison.OrdinalIgnoreCase)
                    ? header
                    : $"{header}; Path=/"
            );
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
        foreach (var (clientKey, cachedSession) in SessionsByClient)
        {
            if (cachedSession.LastSeen < expiry)
            {
                SessionsByClient.TryRemove(clientKey, out _);
            }
        }
    }

    private sealed record CachedSession(MongoId SessionId, DateTimeOffset LastSeen);
}
