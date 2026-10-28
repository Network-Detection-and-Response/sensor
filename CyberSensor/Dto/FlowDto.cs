namespace CyberSensor.Dto;

/// <summary>
/// Одна агрегированная flow-запись для отправки на бэкенд.
/// </summary>
public sealed record FlowDto
{
    public required string SourceIp { get; init; }

    public required int SourcePort { get; init; }

    public required string DestinationIp { get; init; }

    public required int DestinationPort { get; init; }

    public required int Protocol { get; init; }

    public required long PacketCount { get; init; }

    public required long ByteCount { get; init; }

    public required long FirstSeenUnixMs { get; init; }

    public required long LastSeenUnixMs { get; init; }

    public required long DurationUnixMs { get; init; }

    public string? TcpFlags { get; init; }

    public string? SourceMac { get; init; }

    public string? DestinationMac { get; init; }
}
