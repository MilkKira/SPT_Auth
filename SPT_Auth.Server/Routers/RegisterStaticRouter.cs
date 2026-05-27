
using SPT_Auth.Server.Controllers;
using SPT_Auth.Server.Models;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.DI;
using SPTarkov.Server.Core.Models.Eft.Common;
using SPTarkov.Server.Core.Utils;


namespace SPT_Auth.Server.Routers;

[Injectable]
public class RegisterStaticRouter(RegisterController registerController, HttpResponseUtil httpResponseUtil, JsonUtil jsonUtil)
    : StaticRouter(
        jsonUtil,
        [
            new RouteAction<RegisterRequestData>(
                "/launcher/profile/check",
                async (url, info, sessionID, _) => await Check(registerController, url, info, sessionID)
            ),
            new RouteAction<RegisterRequestData>(
                "/api/register",
                async (url, info, sessionID, _) => await Register(registerController, url, info, sessionID)
            ),
            new RouteAction<EmptyRequestData>(
                "/api/register/editions",
                async (_, _, _, _) => await GetEditions(registerController, httpResponseUtil)
            ),
        ]
    )
{
    /** 处理启动器登录校验请求，密码正确时返回存档 id，否则返回 FAILED。 */
    private static ValueTask<string> Check(RegisterController registerController, string url, RegisterRequestData info, SPTarkov.Server.Core.Models.Common.MongoId sessionID)
    {
        var output = registerController.Check(info);
        return new ValueTask<string>(output.IsEmpty ? "FAILED" : output.ToString());
    }
    
    /** 处理注册请求，创建成功时返回新账号存档 id。 */
    private static async ValueTask<string> Register(RegisterController registerController, string url, RegisterRequestData info, SPTarkov.Server.Core.Models.Common.MongoId sessionID)
    {
        var output = await registerController.Register(info);
        return output.IsEmpty ? string.Empty : output.ToString();
    }

    /** 处理版本列表请求，返回服务器当前允许创建的版本名称。 */
    private static ValueTask<string> GetEditions(RegisterController registerController, HttpResponseUtil httpResponseUtil)
    {
        return new ValueTask<string>(httpResponseUtil.NoBody(registerController.GetEditions()));
    }
}