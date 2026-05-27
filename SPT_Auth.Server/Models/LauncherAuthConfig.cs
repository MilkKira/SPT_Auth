namespace SPT_Auth.Server.Models;

public record LauncherAuthConfig
{
    public bool EnabledRegister { get; init; } = true;
}
