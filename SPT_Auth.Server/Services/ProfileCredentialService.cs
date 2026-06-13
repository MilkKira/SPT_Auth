using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.Models.Common;
using SPTarkov.Server.Core.Models.Eft.Profile;
using SPTarkov.Server.Core.Servers;

namespace SPT_Auth.Server.Services;

[Injectable(InjectionType.Singleton)]
public class ProfileCredentialService(SaveServer saveServer)
{
    private const string AuthDataKey = "launcherAuth";

    /**
     * 判断账号是否已经在 Profile 中保存过密码。
     */
    public bool Exists(string? username)
    {
        return !string.IsNullOrWhiteSpace(username)
               && TryGetProfileByUsername(username, out var profile)
               && TryGetCredential(profile, out _);
    }

    /**
     * 把密码以 SHA256 哈希形式保存到 Profile。
     */
    public async Task<bool> SetPasswordAsync(MongoId profileId, string password)
    {
        if (profileId.IsEmpty || string.IsNullOrWhiteSpace(password)) return false;

        SptProfile profile;
        try
        {
            profile = saveServer.GetProfile(profileId);
            // 非空检查
            if (profile?.ProfileInfo?.Username is null)
                return false;
            // 禁止密码与账户相同
            if (password == profile.ProfileInfo.Username)
                return false;
        }
        catch
        {
            return false;
        }

        profile.ExtensionData ??= [];
        profile.ExtensionData[AuthDataKey] = new ProfileCredential
        {
            PasswordHash = HashPassword(password)
        };

        await saveServer.SaveProfileAsync(profileId);
        return true;
    }

    /**
     * 校验用户名和密码是否匹配，成功时返回对应的存档 id。
     */
    public MongoId Validate(string? username, string? password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password)) return MongoId.Empty();

        if (!TryGetProfileByUsername(username, out var profile) || !TryGetCredential(profile, out var credential))
            return MongoId.Empty();

        var expectedHash = Encoding.UTF8.GetBytes(credential.PasswordHash);
        var actualHash = Encoding.UTF8.GetBytes(HashPassword(password));

        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash)
            ? profile.ProfileInfo?.ProfileId ?? MongoId.Empty()
            : MongoId.Empty();
    }

    private bool TryGetProfileByUsername(string username, out SptProfile profile)
    {
        profile = saveServer
            .GetProfiles()
            .Values
            .FirstOrDefault(profile =>
                string.Equals(profile.ProfileInfo?.Username, username, StringComparison.OrdinalIgnoreCase)
            )!;

        return profile is not null;
    }

    private static bool TryGetCredential(SptProfile profile, out ProfileCredential credential)
    {
        credential = default!;

        if (profile.ExtensionData is null || !profile.ExtensionData.TryGetValue(AuthDataKey, out var value))
            return false;

        credential = value switch
        {
            ProfileCredential data => data,
            JsonElement element => element.Deserialize<ProfileCredential>()!,
            _ => JsonSerializer.Deserialize<ProfileCredential>(JsonSerializer.Serialize(value))!
        };

        return !string.IsNullOrWhiteSpace(credential?.PasswordHash);
    }

    private static string HashPassword(string password)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password))).ToLowerInvariant();
    }

    private sealed record ProfileCredential
    {
        public string PasswordHash { get; init; } = "";
    }
}