namespace CyberSensor.Models;

/// <summary>
/// Метаданные одного перехваченного пакета (без payload).
/// </summary>
public readonly record struct PacketMeta(
    long TimestampUnixMs,
    FlowKey Key,
    int TotalLength,
    TcpFlags TcpFlags,
    MacAddress SourceMac,
    MacAddress DestinationMac);
