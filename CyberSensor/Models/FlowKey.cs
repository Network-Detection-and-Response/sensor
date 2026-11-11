namespace CyberSensor.Models;

/// <summary>Ключ сессии (5-tuple), иммутабельный. IEquatable + быстрый GetHashCode генерируются автоматически.</summary>
public readonly record struct FlowKey(
    IpAddr SrcIp,
    IpAddr DstIp,
    ushort SrcPort,
    ushort DstPort,
    byte Protocol)   // 6=TCP, 17=UDP, 1=ICMP
{
    /// <summary>Извлекает ключ сессии из разобранного пакета (zero-alloc).</summary>
    public static FlowKey FromPacket(in ParsedPacket packet) =>
        new(packet.SrcIp, packet.DstIp, packet.SrcPort, packet.DstPort, packet.Protocol);
}
