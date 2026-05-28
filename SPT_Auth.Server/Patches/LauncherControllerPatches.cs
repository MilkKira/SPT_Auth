using HarmonyLib;
using Microsoft.Extensions.DependencyInjection;
using SPT_Auth.Server.Services;
using System.Text.Json;
using SPTarkov.Server.Core.Callbacks;
using SPTarkov.Server.Core.Controllers;
using SPTarkov.Server.Core.DI;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Models.Eft.Launcher;

namespace SPT_Auth.Server.Patches;

[HarmonyPatch]
public static class LauncherControllerPatches
{
    [HarmonyPatch(typeof(LauncherCallbacks), nameof(LauncherCallbacks.Login))]
    [HarmonyPrefix]
    public static bool LauncherCallbackLoginPrefix(LoginRequestData info, ref ValueTask<string> __result)
    {
        if (InternalRegistrationScope.IsActive)
        {
            return true;
        }

        var profileId = GetCredentialService().Validate(info.Username, GetPassword(info));
        __result = new ValueTask<string>(profileId.IsEmpty ? "FAILED" : profileId.ToString());
        return false;
    }

    [HarmonyPatch(typeof(LauncherCallbacks), nameof(LauncherCallbacks.Register))]
    [HarmonyPrefix]
    public static bool LauncherCallbackRegisterPrefix(ref ValueTask<string> __result)
    {
        if (InternalRegistrationScope.IsActive)
        {
            return true;
        }

        __result = new ValueTask<string>("FAILED");
        return false;
    }

    [HarmonyPatch(typeof(LauncherV2Callbacks), nameof(LauncherV2Callbacks.Login))]
    [HarmonyPrefix]
    public static bool LauncherV2CallbackLoginPrefix(LoginRequestData info, ref ValueTask<string> __result)
    {
        if (InternalRegistrationScope.IsActive)
        {
            return true;
        }

        var success = !GetCredentialService().Validate(info.Username, GetPassword(info)).IsEmpty;
        __result = new ValueTask<string>(GetHttpResponseUtil().NoBody(success));
        return false;
    }

    [HarmonyPatch(typeof(LauncherV2Callbacks), nameof(LauncherV2Callbacks.Register))]
    [HarmonyPrefix]
    public static bool LauncherV2CallbackRegisterPrefix(ref ValueTask<string> __result)
    {
        if (InternalRegistrationScope.IsActive)
        {
            return true;
        }

        __result = new ValueTask<string>(GetHttpResponseUtil().NoBody(false));
        return false;
    }

    [HarmonyPatch(typeof(LauncherController), nameof(LauncherController.Login))]
    [HarmonyPrefix]
    public static bool LauncherLoginPrefix(LoginRequestData info, ref MongoId __result)
    {
        if (InternalRegistrationScope.IsActive)
        {
            return true;
        }

        __result = GetCredentialService().Validate(info.Username, GetPassword(info));
        return false;
    }

    [HarmonyPatch(typeof(LauncherController), nameof(LauncherController.Register))]
    [HarmonyPrefix]
    public static bool LauncherRegisterPrefix(ref Task<MongoId> __result)
    {
        if (InternalRegistrationScope.IsActive)
        {
            return true;
        }

        __result = Task.FromResult(MongoId.Empty());
        return false;
    }

    [HarmonyPatch(typeof(LauncherV2Controller), nameof(LauncherV2Controller.Login))]
    [HarmonyPrefix]
    public static bool LauncherV2LoginPrefix(LoginRequestData info, ref bool __result)
    {
        if (InternalRegistrationScope.IsActive)
        {
            return true;
        }

        __result = !GetCredentialService().Validate(info.Username, GetPassword(info)).IsEmpty;
        return false;
    }

    [HarmonyPatch(typeof(LauncherV2Controller), nameof(LauncherV2Controller.Register))]
    [HarmonyPrefix]
    public static bool LauncherV2RegisterPrefix(ref Task<bool> __result)
    {
        if (InternalRegistrationScope.IsActive)
        {
            return true;
        }

        __result = Task.FromResult(false);
        return false;
    }

    private static ProfileCredentialService GetCredentialService()
    {
#pragma warning disable CS0618
        return ServiceLocator.ServiceProvider.GetRequiredService<ProfileCredentialService>();
#pragma warning restore CS0618
    }

    private static SPTarkov.Server.Core.Utils.HttpResponseUtil GetHttpResponseUtil()
    {
#pragma warning disable CS0618
        return ServiceLocator.ServiceProvider.GetRequiredService<SPTarkov.Server.Core.Utils.HttpResponseUtil>();
#pragma warning restore CS0618
    }

    private static string? GetPassword(LoginRequestData info)
    {
        if (info.ExtensionData is null || !info.ExtensionData.TryGetValue("password", out var value))
        {
            return null;
        }

        return value switch
        {
            string password => password,
            JsonElement { ValueKind: JsonValueKind.String } element => element.GetString(),
            _ => value?.ToString(),
        };
    }
}
