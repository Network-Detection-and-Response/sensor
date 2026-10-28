namespace CyberSensor.Models;

/// <summary>
/// Агрегированная запись сессии (flow). Мутабельный struct для обновления в hot path.
/// </summary>
public struct FlowRecord
{
    public FlowKey Key;
    public long PacketCount;
    public long ByteCount;
    public long FirstSeenUnixMs;
    public long LastSeenUnixMs;
    public TcpFlags TcpFlags;
    public MacAddress SourceMac;
    public MacAddress DestinationMac;

    public readonly long DurationUnixMs => LastSeenUnixMs - FirstSeenUnixMs;
}
