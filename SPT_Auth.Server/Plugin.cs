using System.Reflection;
using HarmonyLib;
using SPTarkov.Server.Core.Models.External;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.DI;
using SPTarkov.Server.Core.Models.Utils;

namespace SPT_Auth.Server;

[Injectable(TypePriority = OnLoadOrder.PostSptModLoader + 1)]
public class SptAuthPlugin(ISptLogger<SptAuthPlugin> logger) : IOnLoad
{
    /// <summary>
    /// 在服务端 mod 阶段启用认证补丁。
    /// </summary>
    public Task OnLoad()
    {
        new Harmony(Constants.ServerGuid).PatchAll(Assembly.GetExecutingAssembly());
        logger.Info("[SPT Auth] Launcher auth Harmony patches loaded.");
        return Task.CompletedTask;
    }
    
}