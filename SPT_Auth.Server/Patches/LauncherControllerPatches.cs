using System.Text.Json;
using HarmonyLib;
using Microsoft.Extensions.DependencyInjection;
using SPT_Auth.Server.Services;
using SPTarkov.Server.Core.Controllers;
using SPTarkov.Server.Core.DI;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Models.Eft.Launcher;

namespace SPT_Auth.Server.Patches;

[HarmonyPatch]
public static class LauncherControllerPatches
{
    // TODO : CallBacks Patch
    // [HarmonyPatch(typeof(LauncherCallbacks), nameof(LauncherCallbacks.Login))]
    // [HarmonyPrefix]
    // public static bool LauncherCallbackLoginPrefix(LoginRequestData info, ref ValueTask<string> __result)
    // {
    //     if (InternalRegistrationScope.IsActive)
    //     {
    //         return true;
    //     }
    //
    //     var profileId = GetCredentialService().Validate(info.Username, GetPassword(info));
    //     __result = new ValueTask<string>(profileId.IsEmpty ? "FAILED" : profileId.ToString());
    //     return false;
    // }
    //
    // [HarmonyPatch(typeof(LauncherCallbacks), nameof(LauncherCallbacks.Register))]
    // [HarmonyPrefix]
    // public static bool LauncherCallbackRegisterPrefix(ref ValueTask<string> __result)
    // {
    //     if (InternalRegistrationScope.IsActive)
    //     {
    //         return true;
    //     }
    //
    //     __result = new ValueTask<string>("FAILED");
    //     return false;
    // }
    //
    // [HarmonyPatch(typeof(LauncherV2Callbacks), nameof(LauncherV2Callbacks.Login))]
    // [HarmonyPrefix]
    // public static bool LauncherV2CallbackLoginPrefix(LoginRequestData info, ref ValueTask<string> __result)
    // {
    //     if (InternalRegistrationScope.IsActive)
    //     {
    //         return true;
    //     }
    //
    //     var success = !GetCredentialService().Validate(info.Username, GetPassword(info)).IsEmpty;
    //     __result = new ValueTask<string>(GetHttpResponseUtil().NoBody(success));
    //     return false;
    // }
    //
    // [HarmonyPatch(typeof(LauncherV2Callbacks), nameof(LauncherV2Callbacks.Register))]
    // [HarmonyPrefix]
    // public static bool LauncherV2CallbackRegisterPrefix(ref ValueTask<string> __result)
    // {
    //     if (InternalRegistrationScope.IsActive)
    //     {
    //         return true;
    //     }
    //
    //     __result = new ValueTask<string>(GetHttpResponseUtil().NoBody(false));
    //     return false;
    // }
    /**
     * LauncherController Login
     */
    [HarmonyPatch(typeof(LauncherController), nameof(LauncherController.Login))]
    [HarmonyPrefix]
    public static bool LauncherLoginPrefix(LoginRequestData info, ref MongoId __result)
    {
        if (InternalRegistrationScope.IsActive) return true;

        var password = GetPassword(info);
        var validation = GetCredentialService().ValidateDetailed(info.Username, password);
        __result = validation.ProfileId;
        LogLauncherAuth("LauncherController.Login", info.Username, password, validation.Status, !__result.IsEmpty, __result.ToString());
        return false;
    }

    /**
    * LauncherController Register
    */
    [HarmonyPatch(typeof(LauncherController), nameof(LauncherController.Register))]
    [HarmonyPrefix]
    public static bool LauncherRegisterPrefix(ref Task<MongoId> __result)
    {
        if (InternalRegistrationScope.IsActive) return true;

        __result = Task.FromResult(MongoId.Empty());
        return false;
    }

    /**
    * LauncherV2Controller Login
    */
    [HarmonyPatch(typeof(LauncherV2Controller), nameof(LauncherV2Controller.Login))]
    [HarmonyPrefix]
    public static bool LauncherV2LoginPrefix(LoginRequestData info, ref bool __result)
    {
        if (InternalRegistrationScope.IsActive) return true;

        var password = GetPassword(info);
        var validation = GetCredentialService().ValidateDetailed(info.Username, password);
        __result = !validation.ProfileId.IsEmpty;
        LogLauncherAuth("LauncherV2Controller.Login", info.Username, password, validation.Status, __result, validation.ProfileId.ToString());
        return false;
    }

    /**
    * LauncherV2Controller Register
    */
    [HarmonyPatch(typeof(LauncherV2Controller), nameof(LauncherV2Controller.Register))]
    [HarmonyPrefix]
    public static bool LauncherV2RegisterPrefix(ref Task<bool> __result)
    {
        if (InternalRegistrationScope.IsActive) return true;

        __result = Task.FromResult(false);
        return false;
    }

    private static ProfileCredentialService GetCredentialService()
    {
#pragma warning disable CS0618
        return ServiceLocator.ServiceProvider.GetRequiredService<ProfileCredentialService>();
#pragma warning restore CS0618
    }

    private static void LogLauncherAuth(
        string source,
        string? username,
        string? password,
        CredentialValidationStatus status,
        bool success,
        string profileId
    )
    {
        var message = $"[SPT Auth] {source} result username='{SanitizeUsername(username)}' success={success} reason={status} passwordProvided={!string.IsNullOrWhiteSpace(password)} profileId='{profileId}'";
        if (success)
            SptAuthPlugin.Logger?.Info(message);
        else
            SptAuthPlugin.Logger?.Warning(message);
    }
    private static string SanitizeUsername(string? username)
    {
        return string.IsNullOrWhiteSpace(username) ? "<empty>" : username.Trim();
    }

    private static string? GetPassword(LoginRequestData info)
    {
        if (info.ExtensionData is null || !info.ExtensionData.TryGetValue("password", out var value)) return null;

        return value switch
        {
            string password => password,
            JsonElement { ValueKind: JsonValueKind.String } element => element.GetString(),
            _ => value?.ToString()
        };
    }
}