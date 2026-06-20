using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Reflection;
using System.Text;
using HarmonyLib;
using Microsoft.AspNetCore.Http;

namespace SPT_Auth.Server.Patches;

/// <summary>
/// Allows a Fika notification WebSocket to reconnect without leaving the
/// player attached to a stale socket.
/// </summary>
[HarmonyPatch]
public static class FikaNotificationWebSocketPatches
{
    private const string NotificationWebSocketTypeName = "FikaServer.WebSockets.NotificationWebSocket";
    private const string ClientWebSocketsFieldName = "clientWebSockets";

    [HarmonyPrepare]
    public static bool Prepare()
    {
        return AccessTools.TypeByName(NotificationWebSocketTypeName) is not null;
    }

    [HarmonyTargetMethod]
    public static MethodBase? TargetMethod()
    {
        var notificationWebSocketType = AccessTools.TypeByName(NotificationWebSocketTypeName);
        return notificationWebSocketType is null
            ? null
            : AccessTools.Method(
                notificationWebSocketType,
                "OnConnection",
                [typeof(WebSocket), typeof(HttpContext), typeof(string)]
            );
    }

    [HarmonyPrefix]
    public static void Prefix(object __instance, WebSocket ws, HttpContext context)
    {
        if (!TryGetSessionId(context.Request.Headers.Authorization.ToString(), out var sessionId))
        {
            return;
        }

        var field = AccessTools.Field(__instance.GetType(), ClientWebSocketsFieldName);
        if (
            field?.GetValue(__instance)
                is not ConcurrentDictionary<string, WebSocket> clientWebSockets
            || !clientWebSockets.TryGetValue(sessionId, out var previousSocket)
            || ReferenceEquals(previousSocket, ws)
        )
        {
            return;
        }

        // The original Fika implementation uses TryAdd and returns early when
        // the session already exists. Removing only the observed old mapping
        // lets the original method register the replacement and preserves the
        // existing PresenceService entry.
        ((ICollection<KeyValuePair<string, WebSocket>>)clientWebSockets).Remove(
            new KeyValuePair<string, WebSocket>(sessionId, previousSocket)
        );
    }

    private static bool TryGetSessionId(string authorizationHeader, out string sessionId)
    {
        sessionId = string.Empty;

        if (string.IsNullOrWhiteSpace(authorizationHeader))
        {
            return false;
        }

        var separatorIndex = authorizationHeader.IndexOf(' ');
        if (separatorIndex <= 0)
        {
            return false;
        }

        var encodedCredentials = authorizationHeader[(separatorIndex + 1)..].Trim();
        if (encodedCredentials.Length == 0)
        {
            return false;
        }

        try
        {
            var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
            var credentialsSeparatorIndex = credentials.IndexOf(':');
            sessionId = (
                credentialsSeparatorIndex >= 0
                    ? credentials[..credentialsSeparatorIndex]
                    : credentials
            ).Trim();

            return sessionId.Length > 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
