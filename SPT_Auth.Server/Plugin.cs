using System.Reflection;
using HarmonyLib;
using SPTarkov.Server.Core.Models.External;

namespace SPT_Auth.Server;

public class Plugin : IPreSptLoadModAsync
{
    /** SPT 服务端模组预加载入口。认证服务、控制器和路由由 SPT DI 自动发现并注入。 */
    public Task PreSptLoadAsync()
    {
        new Harmony(Constants.ServerGuid).PatchAll(Assembly.GetExecutingAssembly());
        Console.WriteLine("[SPT Auth] Launcher auth Harmony patches loaded.");
        return Task.CompletedTask;
    }
}
