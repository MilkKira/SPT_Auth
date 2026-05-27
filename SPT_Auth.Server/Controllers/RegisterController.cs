
using SPT_Auth.Server.Models;
using SPT_Auth.Server.Services;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.Controllers;
using SPTarkov.Server.Core.Models.Common;


namespace SPT_Auth.Server.Controllers;

[Injectable]
public class RegisterController(
    LauncherController launcherController,
    LauncherAuthConfigService configService,
    LauncherAuthStore authStore
)
{
    /** 校验用户名和密码，成功时返回账号对应的存档 id。 */
    public MongoId Check(RegisterRequestData info)
    {
        var authProfileId = authStore.Validate(info.Username, info.Password);
        if (!authProfileId.IsEmpty)
        {
            return authProfileId;
        }

        return TryInitializeLegacyPassword(info);
    }

    /** 创建带密码的新账号，并同步创建 SPT 存档。 */
    public async Task<MongoId> Register(RegisterRequestData info)
    {
        if (!IsRegisterEnabled())
        {
            return MongoId.Empty();
        }

        if (!IsRegisterRequestValid(info))
        {
            return MongoId.Empty();
        }
        
        var profileId = await launcherController.Register(
            new SPTarkov.Server.Core.Models.Eft.Launcher.RegisterData
            {
                Username = info.Username,
                Edition = info.Edition,
            }
        );

        if (profileId.IsEmpty)
        {
            return MongoId.Empty();
        }
        
        return profileId;
    }
    

    /** 返回当前服务器允许创建的账号版本列表。 */
    public List<string> GetEditions()
    {
        return launcherController.Connect().Editions ?? [];
    }

    /** 旧账号没有补丁密码记录时，用当前输入密码初始化密码并返回存档 id。 */
    private MongoId TryInitializeLegacyPassword(RegisterRequestData info)
    {
        if (
            string.IsNullOrWhiteSpace(info.Username)
            || string.IsNullOrWhiteSpace(info.Password)
            || authStore.Exists(info.Username)
        )
        {
            return MongoId.Empty();
        }

        var profileId = launcherController.Login(
            new SPTarkov.Server.Core.Models.Eft.Launcher.LoginRequestData
            {
                Username = info.Username,
            }
        );

        if (profileId.IsEmpty)
        {
            return MongoId.Empty();
        }

        authStore.Create(info.Username, info.Password, profileId, null);
        return profileId;
    }

    /** 判断当前配置是否允许开放新账号注册。 */
    private bool IsRegisterEnabled()
    {
        return configService.Config.EnabledRegister;
    }

    /** 检查注册请求的用户名、密码和版本是否满足最小要求。 */
    private static bool IsRegisterRequestValid(RegisterRequestData info)
    {
        return !string.IsNullOrWhiteSpace(info.Username)
            && info.Username.Length <= 15
            && !string.IsNullOrWhiteSpace(info.Password)
            && !string.IsNullOrWhiteSpace(info.Edition);
    }
}