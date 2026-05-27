using System.Security.Cryptography;
using System.Text.Json;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.Models.Common;


namespace SPT_Auth.Server.Services;

[Injectable(InjectionType.Singleton)]
public class LauncherAuthStore
{
    private const int HashIterations = 100_000;
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private readonly string storePath = Path.Combine("user", "launcher-auth", "accounts.json");
    private readonly object storeLock = new();
    private Dictionary<string, AccountAuthRecord>? accounts;

    /** 判断账号是否已经存在于补丁插件的认证存储中。 */
    public bool Exists(string? username)
    {
        return !string.IsNullOrWhiteSpace(username) && LoadAccounts().ContainsKey(username);
    }

    /** 创建账号认证记录，并把密码以 PBKDF2 哈希形式写入磁盘。 */
    public void Create(string username, string password, MongoId profileId, string? email)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = HashPassword(password, salt);
        var data = LoadAccounts();

        data[username] = new AccountAuthRecord
        {
            Username = username,
            ProfileId = profileId.ToString(),
            PasswordHash = Convert.ToBase64String(hash),
            PasswordSalt = Convert.ToBase64String(salt),
            Email = email,
        };

        SaveAccounts(data);
    }

    /** 校验用户名和密码是否匹配，成功时返回对应的存档 id。 */
    public MongoId Validate(string? username, string? password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return MongoId.Empty();
        }

        var data = LoadAccounts();
        if (!data.TryGetValue(username, out var account))
        {
            return MongoId.Empty();
        }

        var salt = Convert.FromBase64String(account.PasswordSalt);
        var expectedHash = Convert.FromBase64String(account.PasswordHash);
        var actualHash = HashPassword(password, salt);

        return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash)
            ? new MongoId(account.ProfileId)
            : MongoId.Empty();
    }

    /** 从磁盘读取认证记录，首次访问时初始化缓存。 */
    private Dictionary<string, AccountAuthRecord> LoadAccounts()
    {
        lock (storeLock)
        {
            if (accounts is not null)
            {
                return accounts;
            }

            if (!File.Exists(storePath))
            {
                accounts = new Dictionary<string, AccountAuthRecord>(StringComparer.OrdinalIgnoreCase);
                return accounts;
            }

            var json = File.ReadAllText(storePath);
            accounts =
                JsonSerializer.Deserialize<Dictionary<string, AccountAuthRecord>>(json)
                ?? new Dictionary<string, AccountAuthRecord>(StringComparer.OrdinalIgnoreCase);
            accounts = new Dictionary<string, AccountAuthRecord>(accounts, StringComparer.OrdinalIgnoreCase);
            return accounts;
        }
    }

    /** 将认证记录缓存序列化保存到 user/launcher-auth/accounts.json。 */
    private void SaveAccounts(Dictionary<string, AccountAuthRecord> data)
    {
        lock (storeLock)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(storePath)!);
            File.WriteAllText(storePath, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    /** 使用 PBKDF2 从明文密码和盐派生固定长度哈希。 */
    private static byte[] HashPassword(string password, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, HashIterations, HashAlgorithmName.SHA256, HashSize);
    }

    private sealed record AccountAuthRecord
    {
        public string Username { get; init; } = "";
        public string ProfileId { get; init; } = "";
        public string PasswordHash { get; init; } = "";
        public string PasswordSalt { get; init; } = "";
        public string? Email { get; init; }
    }
}
