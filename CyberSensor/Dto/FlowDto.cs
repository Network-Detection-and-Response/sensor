using System.Text.Json.Serialization;

namespace CyberSensor.Dto;

/// <summary>
/// Одна агрегированная flow-запись для отправки на бэкенд (строгий snake_case-контракт).
/// </summary>
public sealed record FlowDto
{
    [JsonPropertyName("src_ip")]  public required string SrcIp { get; init; }
    [JsonPropertyName("src_mac")] public required string SrcMac { get; init; }
    [JsonPropertyName("dst_ip")]  public required string DstIp { get; init; }
    [JsonPropertyName("dst_mac")] public required string DstMac { get; init; }
    [JsonPropertyName("src_port")] public required ushort SrcPort { get; init; }
    [JsonPropertyName("dst_port")] public required ushort DstPort { get; init; }
    [JsonPropertyName("protocol")] public required string Protocol { get; init; }
    [JsonPropertyName("duration_ms")] public required long DurationMs { get; init; }
    [JsonPropertyName("total_packets")] public required long TotalPackets { get; init; }
    [JsonPropertyName("total_bytes")] public required long TotalBytes { get; init; }
    [JsonPropertyName("tcp_flags")] public required TcpFlagsDto TcpFlags { get; init; }
}
