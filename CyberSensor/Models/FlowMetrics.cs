namespace CyberSensor.Models;

/// <summary>Метрики сессии (flow). Мутабельный struct для обновления в hot path без аллокаций.</summary>
public struct FlowMetrics
{
    public MacAddress SrcMac;   // L2 для топологии сети
    public MacAddress DstMac;
    public long FirstSeenMs;    // мс
    public long LastSeenMs;     // мс
    public long TotalPackets;
    public long TotalBytes;
    public int SynCount;        // пакеты с TCP SYN
    public int AckCount;        // пакеты с TCP ACK
    public int RstCount;        // пакеты с TCP RST

    /// <summary>Длительность сессии для JSON-контракта (duration_ms).</summary>
    public readonly long DurationMs => Math.Max(0L, LastSeenMs - FirstSeenMs);

    /// <summary>Начальная метрика из первого пакета сессии (zero-alloc).</summary>
    public static FlowMetrics CreateFromFirstPacket(in ParsedPacket packet, long timestampMs)
    {
        FlowMetrics m = default;
        m.SrcMac = packet.SrcMac;
        m.DstMac = packet.DstMac;
        m.FirstSeenMs = timestampMs;
        m.LastSeenMs = timestampMs;
        m.TotalPackets = 1;
        m.TotalBytes = packet.TotalBytes;
        m.CountFlags(packet.TcpFlags);
        return m;
    }

    /// <summary>Накопление следующего пакета (zero-alloc, мутация на месте).</summary>
    public void AddPacket(in ParsedPacket packet, long timestampMs)
    {
        if (timestampMs > LastSeenMs) LastSeenMs = timestampMs;
        TotalPackets++;
        TotalBytes += packet.TotalBytes;
        CountFlags(packet.TcpFlags);
    }

    private void CountFlags(TcpFlags flags)
    {
        if ((flags & TcpFlags.Syn) != 0) SynCount++;
        if ((flags & TcpFlags.Ack) != 0) AckCount++;
        if ((flags & TcpFlags.Rst) != 0) RstCount++;
    }
}
