using System.Collections.Concurrent;
using System.Text;
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
    private const string CompatibilityCookieName = "SPT_AUTH_SESSION";
    private const string GameConfigPath = "/client/game/config";
    private const string FikaPathPrefix = "/fika";
    private const string SessionContextItemName = "SPT_Auth.SessionId";
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(10);
    private static readonly string[] SessionHeaderNames =
    [
        "X-SPT-Session-Id",
        "X-SPT-Session",
        "X-Session-Id"
    ];
    private static readonly ConcurrentDictionary<string, ConcurrentDictionary<MongoId, DateTimeOffset>> SessionsByClient = new();

    [HarmonyPrefix]
    public static void Prefix(HttpContext context)
    {
        context.Response.OnStarting(NormalizeSessionCookies, context);

        if (TryGetCookieSessionId(context.Request.Headers.Cookie, SessionCookieName, out var sessionId))
        {
            ObserveAuthenticatedSession(context, sessionId);
            return;
        }

        if (!IsSessionRecoveryPath(context.Request.Path))
        {
            return;
        }

        if (
            TryGetCookieSessionId(
                context.Request.Headers.Cookie,
                CompatibilityCookieName,
                out sessionId
            )
            || TryGetBasicAuthorizationSessionId(context, out sessionId)
            || TryGetExplicitSessionHeader(context, out sessionId)
            || TryGetUniqueCachedSession(context, out sessionId)
        )
        {
            InjectSessionCookie(context, sessionId);
            ObserveAuthenticatedSession(context, sessionId);
        }
    }

    /// <summary>
    /// Records a session whose identity was established independently of the
    /// potentially missing PHPSESSID cookie, such as a Fika Basic-authenticated
    /// WebSocket connection.
    /// </summary>
    internal static void ObserveAuthenticatedSession(HttpContext context, MongoId sessionId)
    {
        if (sessionId.IsEmpty)
        {
            return;
        }

        context.Items[SessionContextItemName] = sessionId;

        var clientKey = GetClientKey(context);
        var observedSessions = SessionsByClient.GetOrAdd(clientKey, static _ => new());
        observedSessions[sessionId] = DateTimeOffset.UtcNow;
        RemoveExpiredSessions();
    }

    private static bool TryGetUniqueCachedSession(HttpContext context, out MongoId sessionId)
    {
        var clientKey = GetClientKey(context);
        if (
            !SessionsByClient.TryGetValue(clientKey, out var clientSessions)
        )
        {
            sessionId = MongoId.Empty();
            return false;
        }

        RemoveExpiredSessions(clientKey, clientSessions);

        // Reverse proxies can make multiple players share the same apparent IP
        // and Fika clients commonly use the same User-Agent. Recovering the most
        // recently seen session in that case would silently impersonate another
        // player. Only recover when the client key identifies one active session.
        var candidates = clientSessions.ToArray();
        if (candidates.Length != 1)
        {
            sessionId = MongoId.Empty();
            return false;
        }

        (sessionId, _) = candidates[0];
        return !sessionId.IsEmpty;
    }

    private static void InjectSessionCookie(HttpContext context, MongoId sessionId)
    {
        // HttpServer has not read Request.Cookies yet, so updating the raw
        // header here makes the recovered value visible to the original code.
        var existingCookies = context.Request.Headers.Cookie.ToString();
        context.Request.Headers.Cookie = string.IsNullOrWhiteSpace(existingCookies)
            ? $"{SessionCookieName}={sessionId}"
            : $"{existingCookies}; {SessionCookieName}={sessionId}";
    }

    private static Task NormalizeSessionCookies(object state)
    {
        var context = (HttpContext)state;
        var response = context.Response;
        var normalizedHeaders = new List<string>();

        if (!response.Headers.TryGetValue("Set-Cookie", out var setCookieHeaders))
        {
            setCookieHeaders = StringValues.Empty;
        }

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

        if (
            context.Items.TryGetValue(SessionContextItemName, out var value)
            && value is MongoId sessionId
            && !sessionId.IsEmpty
        )
        {
            normalizedHeaders.RemoveAll(
                header => header.StartsWith(
                    $"{CompatibilityCookieName}=",
                    StringComparison.OrdinalIgnoreCase
                )
            );
            normalizedHeaders.Add(
                $"{CompatibilityCookieName}={sessionId}; Path=/; HttpOnly; SameSite=Lax"
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

    private static bool TryGetCookieSessionId(
        StringValues cookieHeaders,
        string cookieName,
        out MongoId sessionId
    )
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
                if (
                    separatorIndex <= 0
                    || !cookie[..separatorIndex].Equals(
                        cookieName,
                        StringComparison.OrdinalIgnoreCase
                    )
                )
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

    private static bool TryGetBasicAuthorizationSessionId(
        HttpContext context,
        out MongoId sessionId
    )
    {
        var authorization = context.Request.Headers.Authorization.ToString();
        var separatorIndex = authorization.IndexOf(' ');
        if (
            separatorIndex <= 0
            || !authorization[..separatorIndex].Equals(
                "Basic",
                StringComparison.OrdinalIgnoreCase
            )
        )
        {
            sessionId = MongoId.Empty();
            return false;
        }

        try
        {
            var credentials = Encoding.UTF8.GetString(
                Convert.FromBase64String(authorization[(separatorIndex + 1)..].Trim())
            );
            var credentialsSeparatorIndex = credentials.IndexOf(':');
            var value = (
                credentialsSeparatorIndex >= 0
                    ? credentials[..credentialsSeparatorIndex]
                    : credentials
            ).Trim();

            return TryParseSessionId(value, out sessionId);
        }
        catch (FormatException)
        {
            sessionId = MongoId.Empty();
            return false;
        }
    }

    private static bool TryGetExplicitSessionHeader(
        HttpContext context,
        out MongoId sessionId
    )
    {
        foreach (var headerName in SessionHeaderNames)
        {
            if (
                context.Request.Headers.TryGetValue(headerName, out var values)
                && TryParseSessionId(values.ToString().Trim(), out sessionId)
            )
            {
                return true;
            }
        }

        sessionId = MongoId.Empty();
        return false;
    }

    private static bool TryParseSessionId(string value, out MongoId sessionId)
    {
        if (MongoId.IsValidMongoId(value))
        {
            sessionId = new MongoId(value);
            return !sessionId.IsEmpty;
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
