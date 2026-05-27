

using SPTarkov.Server.Core.Models.Spt.Mod;
using Range = SemanticVersioning.Range;
using Version = SemanticVersioning.Version;

namespace SPT_Auth.Server;

public sealed record MetaData : AbstractModMetadata
{
    public override string ModGuid { get; init; } = Constants.ServerGuid;
    public override string Name { get; init; } = Constants.ServerPluginName;
    public override string Author { get; init; } = "牛奶";
    public override List<string>? Contributors { get; init; } = [];
    public override Version Version { get; init; } = new("1.0.0");
    public override Range SptVersion { get; init; } = new("~4.0.9");
    public override List<string>? Incompatibilities { get; init; } = [];
    public override Dictionary<string, Range>? ModDependencies { get; init; } = [];
    public override string? Url { get; init; } = "https://github.com/";
    public override bool? IsBundleMod { get; init; } = false;
    public override string License { get; init; } = "MIT";
}

internal static class Constants
{
    public const string ServerGuid = "com.milkkira.easyAuth.server";

    public const string ServerPluginName = "牛奶的简单认证系统";
    
}
