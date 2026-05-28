using System.Text.RegularExpressions;
using SPT_Auth.Server.Models;
using SPT_Auth.Server.Services;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.Controllers;
using SPTarkov.Server.Core.Models.Common;

namespace SPT_Auth.Server.Controllers;

[Injectable]
public class AuthenticationController(
    LauncherController launcherController,
    AuthConfigService configService,
    ProfileCredentialService credentialService
)
{
    /** 校验用户名和密码，成功时返回账号对应的存档 id。 */
    public async Task<MongoId> LoginAsync(AuthRequestData request)
    {
        var profileId = credentialService.Validate(request.Username, request.Password);
        if (!profileId.IsEmpty)
        {
            return profileId;
        }
        
        if (!configService.Config.CompatibleWithLegacyAccount)
        {
            return MongoId.Empty();
        }
        else
        {
            return await InitializeLegacyProfilePasswordAsync(request);
        }
        
    }

    /** 创建带密码的新账号，并同步创建 SPT 存档。 */
    public async Task<MongoId> RegisterAsync(AuthRequestData request)
    {
        if (!configService.Config.EnableRegistration || !IsRegistrationRequestValid(request))
        {
            return MongoId.Empty();
        }

        MongoId profileId;
        using (InternalRegistrationScope.Begin())
        {
            profileId = await launcherController.Register(
                new SPTarkov.Server.Core.Models.Eft.Launcher.RegisterData
                {
                    Username = request.Username,
                    Edition = request.Edition,
                }
            );
        }

        if (profileId.IsEmpty)
        {
            return MongoId.Empty();
        }

        return await credentialService.SetPasswordAsync(profileId, request.Password!)
            ? profileId
            : MongoId.Empty();
    }
    
    /** 旧账号没有密码记录时，用当前输入密码初始化密码并返回存档 id。 */
    private async Task<MongoId> InitializeLegacyProfilePasswordAsync(AuthRequestData request)
    {
        if (
            string.IsNullOrWhiteSpace(request.Username)
            || string.IsNullOrWhiteSpace(request.Password)
            || credentialService.Exists(request.Username)
        )
        {
            return MongoId.Empty();
        }

        MongoId profileId;
        using (InternalRegistrationScope.Begin())
        {
            profileId = launcherController.Login(
                new SPTarkov.Server.Core.Models.Eft.Launcher.LoginRequestData
                {
                    Username = request.Username,
                }
            );
        }

        if (profileId.IsEmpty)
        {
            return MongoId.Empty();
        }

        return await credentialService.SetPasswordAsync(profileId, request.Password)
            ? profileId
            : MongoId.Empty();
    }

    /** 检查注册请求的用户名、密码和版本是否满足最小要求。 */
    private static bool IsRegistrationRequestValid(AuthRequestData request)
    {
        return !string.IsNullOrWhiteSpace(request.Username)
               && request.Username.Length <= 15
               && !string.IsNullOrWhiteSpace(request.Password)
               && request.Password.Length is >= 6 and <= 16
               && Regex.IsMatch(
                   request.Password,
                   @"^(?=.*[A-Za-z])(?=.*\d).+$"
               )
               && !string.IsNullOrWhiteSpace(request.Edition);
    }
}
