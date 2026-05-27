
using SPT_Auth.Server.Models;
using SPTarkov.DI.Annotations;
using SPTarkov.Server.Core.Utils;


namespace SPT_Auth.Server.Services;

[Injectable(InjectionType.Singleton)]
public class LauncherAuthConfigService
{
    private const string ModFolderName = "SPT.AuthServer";
    private const string ConfigFileName = "config.json";
    private readonly FileUtil fileUtil;
    private readonly JsonUtil jsonUtil;
    private readonly string configPath;

    public LauncherAuthConfig Config { get; }

    /** 初始化注册补丁配置服务，读取插件配置文件，不存在时创建默认配置。 */
    public LauncherAuthConfigService(FileUtil fileUtil, JsonUtil jsonUtil)
    {
        this.fileUtil = fileUtil;
        this.jsonUtil = jsonUtil;
        configPath = Path.Combine(fileUtil.GetModPath(ModFolderName), ConfigFileName);
        Config = LoadOrCreateConfig();
    }

    /** 读取注册补丁配置，读取失败或文件不存在时返回并写入默认配置。 */
    private LauncherAuthConfig LoadOrCreateConfig()
    {
        if (!fileUtil.FileExists(configPath))
        {
            return SaveDefaultConfig();
        }

        var config = jsonUtil.DeserializeFromFile<LauncherAuthConfig>(configPath);
        return config ?? SaveDefaultConfig();
    }

    /** 写入默认注册补丁配置，并返回默认配置对象。 */
    private LauncherAuthConfig SaveDefaultConfig()
    {
        var config = new LauncherAuthConfig();
        fileUtil.WriteFile(configPath, jsonUtil.Serialize(config, true) ?? "{}");
        return config;
    }
}