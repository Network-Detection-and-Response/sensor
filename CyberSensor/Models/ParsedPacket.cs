namespace CyberSensor.Models;

/// <summary>
/// Результат разбора кадра (L2/L3/L4) без payload. Передаётся как структура, аллокаций нет.
/// </summary>
public readonly record struct ParsedPacket(
    MacAddress SrcMac,
    MacAddress DstMac,
    IpAddr SrcIp,
    IpAddr DstIp,
    ushort SrcPort,
    ushort DstPort,
    byte Protocol,        // 6=TCP, 17=UDP, 1=ICMP
    TcpFlags TcpFlags,
    int TotalBytes,
    long TimestampTicks);
