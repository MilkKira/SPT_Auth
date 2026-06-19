using System.Text.RegularExpressions;
using SPT_Auth.Server.Models;
using SPT_Auth.Server.Services;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.Controllers;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Models.Eft.Launcher;
using SPTarkov.Server.Core.Models.Utils;

namespace SPT_Auth.Server.Controllers;

[Injectable]
public class AuthenticationController(
    LauncherController launcherController,
    AuthConfigService configService,
    ProfileCredentialService credentialService,
    ISptLogger<AuthenticationController> logger
)
{
    /**
     * 校验用户名和密码，成功时返回账号对应的存档 id。
     */
    public async Task<MongoId> LoginAsync(AuthRequestData request)
    {
        var validation = credentialService.ValidateDetailed(request.Username, request.Password);
        if (!validation.ProfileId.IsEmpty)
        {
            logger.Info($"[SPT Auth] /launcher/profile/check success username='{SanitizeUsername(request.Username)}' profileId='{validation.ProfileId}' passwordProvided={HasPassword(request)} source=storedCredential");
            return validation.ProfileId;
        }

        logger.Warning($"[SPT Auth] /launcher/profile/check stored credential failed username='{SanitizeUsername(request.Username)}' reason={validation.Status} passwordProvided={HasPassword(request)} legacyCompatible={configService.Config.CompatibleWithLegacyAccount}");

        if (!configService.Config.CompatibleWithLegacyAccount)
        {
            logger.Warning($"[SPT Auth] /launcher/profile/check failed username='{SanitizeUsername(request.Username)}' reason=LegacyCompatibilityDisabled");
            return MongoId.Empty();
        }

        var profileId = await InitializeLegacyProfilePasswordAsync(request);
        logger.Info($"[SPT Auth] /launcher/profile/check legacy initialization result username='{SanitizeUsername(request.Username)}' success={!profileId.IsEmpty} profileId='{profileId}'");
        return profileId;
    }

    /**
     * 创建带密码的新账号，并同步创建 SPT 存档。
     */
    public async Task<MongoId> RegisterAsync(AuthRequestData request)
    {
        if (!configService.Config.EnableRegistration || !IsRegistrationRequestValid(request)) return MongoId.Empty();

        MongoId profileId;
        using (InternalRegistrationScope.Begin())
        {
            profileId = await launcherController.Register(
                new RegisterData
                {
                    Username = request.Username,
                    Edition = request.Edition
                }
            );
        }

        if (profileId.IsEmpty) return MongoId.Empty();

        return await credentialService.SetPasswordAsync(profileId, request.Password!)
            ? profileId
            : MongoId.Empty();
    }

    /**
     * 旧账号没有密码记录时，用当前输入密码初始化密码并返回存档 id。
     */
    private async Task<MongoId> InitializeLegacyProfilePasswordAsync(AuthRequestData request)
    {
        if (string.IsNullOrWhiteSpace(request.Username))
        {
            logger.Warning("[SPT Auth] Legacy password initialization skipped reason=MissingUsername");
            return MongoId.Empty();
        }

        if (string.IsNullOrWhiteSpace(request.Password))
        {
            logger.Warning($"[SPT Auth] Legacy password initialization skipped username='{SanitizeUsername(request.Username)}' reason=MissingPassword");
            return MongoId.Empty();
        }

        if (credentialService.Exists(request.Username))
        {
            logger.Warning($"[SPT Auth] Legacy password initialization skipped username='{SanitizeUsername(request.Username)}' reason=CredentialAlreadyExists");
            return MongoId.Empty();
        }

        MongoId profileId;
        using (InternalRegistrationScope.Begin())
        {
            profileId = launcherController.Login(
                new LoginRequestData
                {
                    Username = request.Username
                }
            );
        }

        if (profileId.IsEmpty)
        {
            logger.Warning($"[SPT Auth] Legacy password initialization failed username='{SanitizeUsername(request.Username)}' reason=OriginalLauncherLoginReturnedEmpty");
            return MongoId.Empty();
        }

        var saved = await credentialService.SetPasswordAsync(profileId, request.Password);
        if (!saved)
            logger.Warning($"[SPT Auth] Legacy password initialization failed username='{SanitizeUsername(request.Username)}' profileId='{profileId}' reason=SavePasswordFailed");

        return saved ? profileId : MongoId.Empty();
    }

    /**
     * 检查注册请求的用户名、密码和版本是否满足最小要求。
     */
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

    private static bool HasPassword(AuthRequestData request)
    {
        return !string.IsNullOrWhiteSpace(request.Password);
    }

    private static string SanitizeUsername(string? username)
    {
        return string.IsNullOrWhiteSpace(username) ? "<empty>" : username.Trim();
    }
}