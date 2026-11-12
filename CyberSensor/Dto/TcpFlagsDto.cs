using System.Text.Json.Serialization;

namespace CyberSensor.Dto;

/// <summary>
/// Счётчики TCP-флагов сессии для JSON-контракта (вложенный объект <c>tcp_flags</c>).
/// </summary>
public sealed record TcpFlagsDto
{
    [JsonPropertyName("syn")] public required int Syn { get; init; }
    [JsonPropertyName("ack")] public required int Ack { get; init; }
    [JsonPropertyName("rst")] public required int Rst { get; init; }
}
