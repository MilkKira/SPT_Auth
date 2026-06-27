using System.Collections;
using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Reflection;
using System.Text;
using HarmonyLib;
using Microsoft.AspNetCore.Http;
using SPTarkov.Server.Core.Models.Common;

namespace SPT_Auth.Server.Patches;

/// <summary>
/// Protects Fika headless WebSocket reconnects from stale socket mappings.
/// </summary>
public static class FikaHeadlessWebSocketPatches
{
    private static readonly TimeSpan HeadlessReconnectGracePeriod =
        TimeSpan.FromSeconds(90);
    private const string HeadlessClientTypeName =
        "FikaServer.WebSockets.HeadlessClientWebSocket";
    private const string HeadlessRequesterTypeName =
        "FikaServer.WebSockets.HeadlessRequesterWebSocket";

    [HarmonyPatch]
    private static class HeadlessClientConnectionPatch
    {
        [HarmonyPrepare]
        public static bool Prepare()
        {
            return AccessTools.TypeByName(HeadlessClientTypeName) is not null;
        }

        [HarmonyTargetMethod]
        public static MethodBase? TargetMethod()
        {
            return GetWebSocketMethod(HeadlessClientTypeName, "OnConnection");
        }

        [HarmonyPrefix]
        public static bool Prefix(
            object __instance,
            WebSocket ws,
            HttpContext context,
            ref Task __result
        )
        {
            if (!TryGetBasicSessionId(context, out var sessionId))
            {
                return true;
            }

            HttpSessionCompatibilityPatches.ObserveAuthenticatedSession(
                context,
                new MongoId(sessionId)
            );

            var existingClientInfo = GetHeadlessClientInfo(
                __instance,
                sessionId
            );
            if (existingClientInfo is null)
            {
                RemovePreviousSocketMapping(
                    __instance,
                    "_headlessWebSockets",
                    sessionId,
                    ws
                );
                return true;
            }

            var webSocketProperty = existingClientInfo
                .GetType()
                .GetProperty("WebSocket");
            var previousSocket = webSocketProperty?.GetValue(existingClientInfo)
                as WebSocket;

            // Preserve the existing HeadlessClientInfo object. It contains the
            // active IN_RAID state, requester and connected player list. Fika's
            // original reconnect path replaces it with READY and deletes the
            // current match before doing so.
            webSocketProperty?.SetValue(existingClientInfo, ws);
            ReplaceSocketMapping(
                __instance,
                "_headlessWebSockets",
                sessionId,
                ws
            );

            __result = CloseReplacedSocket(previousSocket, ws);
            return false;
        }
    }

    [HarmonyPatch]
    private static class HeadlessClientClosePatch
    {
        [HarmonyPrepare]
        public static bool Prepare()
        {
            return AccessTools.TypeByName(HeadlessClientTypeName) is not null;
        }

        [HarmonyTargetMethod]
        public static MethodBase? TargetMethod()
        {
            return GetWebSocketMethod(HeadlessClientTypeName, "OnClose");
        }

        [HarmonyPrefix]
        public static bool Prefix(
            object __instance,
            object[] __args,
            ref Task __result
        )
        {
            if (!TryGetCloseArgs(__args, out var ws, out var sessionId))
            {
                return true;
            }

            var socketMappings = GetSocketMappings(
                __instance,
                "_headlessWebSockets"
            );
            if (socketMappings is null)
            {
                return true;
            }

            if (
                socketMappings.TryGetValue(sessionId, out var currentSocket)
                && !ReferenceEquals(currentSocket, ws)
            )
            {
                __result = Task.CompletedTask;
                return false;
            }

            var closingSession = socketMappings.FirstOrDefault(
                pair => ReferenceEquals(pair.Value, ws)
            ).Key;
            if (string.IsNullOrEmpty(closingSession))
            {
                return true;
            }

            // Fika Headless retries every five seconds and exits after fifteen
            // failed attempts. Preserve the match and IN_RAID state throughout
            // that retry window instead of deleting HeadlessClients immediately.
            _ = RemoveDisconnectedHeadlessAfterGracePeriod(
                __instance,
                closingSession,
                ws
            );
            __result = Task.CompletedTask;
            return false;
        }
    }

    [HarmonyPatch]
    private static class HeadlessRequesterConnectionPatch
    {
        [HarmonyPrepare]
        public static bool Prepare()
        {
            return AccessTools.TypeByName(HeadlessRequesterTypeName) is not null;
        }

        [HarmonyTargetMethod]
        public static MethodBase? TargetMethod()
        {
            return GetWebSocketMethod(HeadlessRequesterTypeName, "OnConnection");
        }

        [HarmonyPrefix]
        public static void Prefix(object __instance, WebSocket ws, HttpContext context)
        {
            if (!TryGetBasicSessionId(context, out var sessionId))
            {
                return;
            }

            HttpSessionCompatibilityPatches.ObserveAuthenticatedSession(
                context,
                new MongoId(sessionId)
            );

            RemovePreviousSocketMapping(
                __instance,
                "requesterWebSockets",
                sessionId,
                ws
            );
        }
    }

    [HarmonyPatch]
    private static class HeadlessRequesterClosePatch
    {
        [HarmonyPrepare]
        public static bool Prepare()
        {
            return AccessTools.TypeByName(HeadlessRequesterTypeName) is not null;
        }

        [HarmonyTargetMethod]
        public static MethodBase? TargetMethod()
        {
            return GetWebSocketMethod(HeadlessRequesterTypeName, "OnClose");
        }

        [HarmonyPrefix]
        public static bool Prefix(
            object __instance,
            object[] __args,
            ref Task __result
        )
        {
            if (!TryGetCloseArgs(__args, out var ws, out var sessionId))
            {
                return true;
            }

            var socketMappings = GetSocketMappings(
                __instance,
                "requesterWebSockets"
            );
            if (
                socketMappings is not null
                && socketMappings.TryGetValue(sessionId, out var currentSocket)
                && !ReferenceEquals(currentSocket, ws)
            )
            {
                __result = Task.CompletedTask;
                return false;
            }

            return true;
        }
    }

    private static MethodBase? GetWebSocketMethod(
        string typeName,
        string methodName
    )
    {
        var type = AccessTools.TypeByName(typeName);
        return type is null
            ? null
            : AccessTools.Method(
                type,
                methodName,
                [typeof(WebSocket), typeof(HttpContext), typeof(string)]
            );
    }

    private static void ReplaceSocketMapping(
        object instance,
        string fieldName,
        string sessionId,
        WebSocket socket
    )
    {
        var mappings = GetSocketMappings(instance, fieldName);
        if (mappings is not null)
        {
            mappings[sessionId] = socket;
        }
    }

    private static void RemovePreviousSocketMapping(
        object instance,
        string fieldName,
        string sessionId,
        WebSocket socket
    )
    {
        var mappings = GetSocketMappings(instance, fieldName);
        if (
            mappings is null
            || !mappings.TryGetValue(sessionId, out var previousSocket)
            || ReferenceEquals(previousSocket, socket)
        )
        {
            return;
        }

        ((ICollection<KeyValuePair<string, WebSocket>>)mappings).Remove(
            new KeyValuePair<string, WebSocket>(sessionId, previousSocket)
        );
    }

    private static ConcurrentDictionary<string, WebSocket>? GetSocketMappings(
        object instance,
        string fieldName
    )
    {
        return AccessTools.Field(instance.GetType(), fieldName)?.GetValue(instance)
            as ConcurrentDictionary<string, WebSocket>;
    }

    private static object? GetHeadlessClientInfo(
        object instance,
        string sessionId
    )
    {
        var headlessServiceField = instance
            .GetType()
            .GetFields(
                BindingFlags.Instance
                    | BindingFlags.Public
                    | BindingFlags.NonPublic
            )
            .FirstOrDefault(
                field =>
                    field.FieldType.FullName
                    == "FikaServer.Services.Headless.HeadlessService"
            );
        var headlessService = headlessServiceField?.GetValue(instance);
        var headlessClients = headlessService
            ?.GetType()
            .GetProperty("HeadlessClients")
            ?.GetValue(headlessService) as IEnumerable;
        if (headlessClients is null)
        {
            return null;
        }

        foreach (var entry in headlessClients)
        {
            if (entry is null)
            {
                continue;
            }

            var entryType = entry.GetType();
            var key = entryType.GetProperty("Key")?.GetValue(entry)?.ToString();
            if (!string.Equals(key, sessionId, StringComparison.Ordinal))
            {
                continue;
            }

            var clientInfo = entryType.GetProperty("Value")?.GetValue(entry);
            return clientInfo;
        }

        return null;
    }

    private static async Task CloseReplacedSocket(
        WebSocket? previousSocket,
        WebSocket replacementSocket
    )
    {
        if (
            previousSocket is null
            || ReferenceEquals(previousSocket, replacementSocket)
            || previousSocket.State
                is WebSocketState.Closed
                    or WebSocketState.Aborted
        )
        {
            return;
        }

        try
        {
            await previousSocket.CloseAsync(
                WebSocketCloseStatus.PolicyViolation,
                "Replaced by reconnected headless client",
                CancellationToken.None
            );
        }
        catch
        {
            // The replacement is already active; failure to close a stale
            // transport must not affect the headless raid.
        }
    }

    private static async Task RemoveDisconnectedHeadlessAfterGracePeriod(
        object instance,
        string sessionId,
        WebSocket disconnectedSocket
    )
    {
        await Task.Delay(HeadlessReconnectGracePeriod);

        var clientInfo = GetHeadlessClientInfo(instance, sessionId);
        var activeSocket = clientInfo
            ?.GetType()
            .GetProperty("WebSocket")
            ?.GetValue(clientInfo) as WebSocket;

        // A reconnect replaced the socket during the grace period.
        if (
            activeSocket is not null
            && !ReferenceEquals(activeSocket, disconnectedSocket)
        )
        {
            return;
        }

        var socketMappings = GetSocketMappings(
            instance,
            "_headlessWebSockets"
        );
        if (
            socketMappings is not null
            && socketMappings.TryGetValue(sessionId, out var mappedSocket)
            && ReferenceEquals(mappedSocket, disconnectedSocket)
        )
        {
            ((ICollection<KeyValuePair<string, WebSocket>>)socketMappings).Remove(
                new KeyValuePair<string, WebSocket>(
                    sessionId,
                    disconnectedSocket
                )
            );
        }

        RemoveHeadlessClientInfo(instance, sessionId, clientInfo);
    }

    private static void RemoveHeadlessClientInfo(
        object instance,
        string sessionId,
        object? expectedClientInfo
    )
    {
        var headlessClients = GetHeadlessClients(instance);
        if (headlessClients is null || expectedClientInfo is null)
        {
            return;
        }

        var tryRemove = headlessClients
            .GetType()
            .GetMethods()
            .FirstOrDefault(
                method =>
                    method.Name == "TryRemove"
                    && method.GetParameters().Length == 2
                    && method.GetParameters()[1].IsOut
            );
        if (tryRemove is null)
        {
            return;
        }

        var key = new MongoId(sessionId);
        var arguments = new object?[] { key, null };
        if (
            tryRemove.Invoke(headlessClients, arguments) is true
            && arguments[1] is not null
            && !ReferenceEquals(arguments[1], expectedClientInfo)
        )
        {
            // A reconnect raced with cleanup. Restore the newer entry.
            var tryAdd = headlessClients
                .GetType()
                .GetMethod("TryAdd");
            tryAdd?.Invoke(headlessClients, [key, arguments[1]]);
        }
    }

    private static object? GetHeadlessClients(object instance)
    {
        var headlessServiceField = instance
            .GetType()
            .GetFields(
                BindingFlags.Instance
                    | BindingFlags.Public
                    | BindingFlags.NonPublic
            )
            .FirstOrDefault(
                field =>
                    field.FieldType.FullName
                    == "FikaServer.Services.Headless.HeadlessService"
            );
        var headlessService = headlessServiceField?.GetValue(instance);
        return headlessService
            ?.GetType()
            .GetProperty("HeadlessClients")
            ?.GetValue(headlessService);
    }

    private static bool TryGetBasicSessionId(
        HttpContext context,
        out string sessionId
    )
    {
        sessionId = string.Empty;
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
            return false;
        }

        try
        {
            var credentials = Encoding.UTF8.GetString(
                Convert.FromBase64String(
                    authorization[(separatorIndex + 1)..].Trim()
                )
            );
            var credentialsSeparatorIndex = credentials.IndexOf(':');
            sessionId = (
                credentialsSeparatorIndex >= 0
                    ? credentials[..credentialsSeparatorIndex]
                    : credentials
            ).Trim();

            return MongoId.IsValidMongoId(sessionId);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool TryGetCloseArgs(
        object[] args,
        out WebSocket ws,
        out string sessionId
    )
    {
        if (
            args.Length >= 3
            && args[0] is WebSocket socket
            && args[2] is string id
        )
        {
            ws = socket;
            sessionId = id;
            return true;
        }

        ws = null!;
        sessionId = string.Empty;
        return false;
    }
}
