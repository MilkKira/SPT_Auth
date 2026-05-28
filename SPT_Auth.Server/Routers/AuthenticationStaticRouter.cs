using SPT_Auth.Server.Controllers;
using SPT_Auth.Server.Models;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.DI;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Models.Eft.Common;
using SPTarkov.Server.Core.Utils;

namespace SPT_Auth.Server.Routers;

[Injectable]
public class AuthenticationStaticRouter(
    AuthenticationController authenticationController,
    HttpResponseUtil httpResponseUtil,
    JsonUtil jsonUtil
)
    : StaticRouter(
        jsonUtil,
        [
            new RouteAction<AuthRequestData>(
                "/launcher/profile/check",
                async (_, request, _, _) => await LoginAsync(authenticationController, request)
            ),
            new RouteAction<AuthRequestData>(
                "/api/register",
                async (_, request, _, _) => await RegisterAsync(authenticationController, request)
            ),
            new RouteAction<EmptyRequestData>(
                "/api/register/editions",
                async (_, _, _, _) => await GetEditionsAsync(authenticationController, httpResponseUtil)
            ),
        ]
    )
{
    /** 处理启动器登录校验请求，密码正确时返回存档 id，否则返回 FAILED。 */
    private static async ValueTask<string> LoginAsync(AuthenticationController authenticationController, AuthRequestData request)
    {
        var profileId = await authenticationController.LoginAsync(request);
        return profileId.IsEmpty ? "FAILED" : profileId.ToString();
    }

    /** 处理注册请求，创建成功时返回新账号存档 id。 */
    private static async ValueTask<string> RegisterAsync(AuthenticationController authenticationController, AuthRequestData request)
    {
        var profileId = await authenticationController.RegisterAsync(request);
        return profileId.IsEmpty ? string.Empty : profileId.ToString();
    }

    /** 处理版本列表请求，返回服务器当前允许创建的版本名称。 */
    private static ValueTask<string> GetEditionsAsync(AuthenticationController authenticationController, HttpResponseUtil httpResponseUtil)
    {
        return new ValueTask<string>(httpResponseUtil.NoBody(authenticationController.GetEditions()));
    }
}
