using System.Text.Json.Serialization;
using SPTarkov.Server.Core.Models.Utils;

namespace SPT_Auth.Server.Models;

public record AuthRequestData : IRequestData
{
    [JsonPropertyName("username")] public string? Username { get; set; }

    [JsonPropertyName("password")] public string? Password { get; set; }

    [JsonPropertyName("edition")] public string? Edition { get; set; }
}