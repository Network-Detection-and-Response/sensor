using CyberSensor.Models;

namespace CyberSensor.Aggregation;

/// <summary>Сводка заблокированного флуда с одного SrcIp (мутабельный struct).</summary>
internal struct DroppedFloodSummary
{
    public MacAddress SrcMac;
    public IpAddr DstIp;       // последний целевой адрес
    public MacAddress DstMac;
    public ushort DstPort;     // последний целевой порт
    public byte Protocol;      // последний протокол
    public long FirstSeenMs;
    public long LastSeenMs;
    public long TotalPackets;
    public long TotalBytes;
    public int SynCount;
    public int AckCount;
    public int RstCount;
}
