namespace SPT_Auth.Server.Models;

public record AuthConfig
{
    public bool EnableRegistration { get; init; } = true;
}
