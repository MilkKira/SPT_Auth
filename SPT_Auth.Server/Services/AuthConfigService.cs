using SPT_Auth.Server.Models;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.Utils;

namespace SPT_Auth.Server.Services;

[Injectable(InjectionType.Singleton)]
public class AuthConfigService
{
    private const string ModFolderName = "SPT.AuthServer";
    private const string ConfigFileName = "config.json";
    private readonly FileUtil fileUtil;
    private readonly JsonUtil jsonUtil;
    private readonly string configPath;

    public AuthConfig Config { get; }

    /** 初始化认证配置服务，读取插件配置文件，不存在时创建默认配置。 */
    public AuthConfigService(FileUtil fileUtil, JsonUtil jsonUtil)
    {
        this.fileUtil = fileUtil;
        this.jsonUtil = jsonUtil;
        configPath = Path.Combine(fileUtil.GetModPath(ModFolderName), ConfigFileName);
        Config = LoadOrCreateConfig();
    }

    /** 读取认证配置，读取失败或文件不存在时返回并写入默认配置。 */
    private AuthConfig LoadOrCreateConfig()
    {
        if (!fileUtil.FileExists(configPath))
        {
            return SaveDefaultConfig();
        }

        var config = jsonUtil.DeserializeFromFile<AuthConfig>(configPath);
        return config ?? SaveDefaultConfig();
    }

    /** 写入默认认证配置，并返回默认配置对象。 */
    private AuthConfig SaveDefaultConfig()
    {
        var config = new AuthConfig();
        fileUtil.WriteFile(configPath, jsonUtil.Serialize(config, true) ?? "{}");
        return config;
    }
}
