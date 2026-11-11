using System.Buffers.Binary;
using CyberSensor.Models;

namespace CyberSensor.Capture;

/// <summary>
/// Парсинг кадра (L2/L3/L4) в <see cref="ParsedPacket"/> без аллокаций.
/// Никогда не выбрасывает исключения на битых/обрезанных пакетах — все срезы только после проверки границ.
/// </summary>
public static class PacketParser
{
    public static bool TryParse(ReadOnlySpan<byte> data, long timestampTicks, out ParsedPacket packet)
    {
        packet = default;
        if (data.Length < 14) return false;

        MacAddress dstMac = MacAddress.FromBytes(data.Slice(0, 6));
        MacAddress srcMac = MacAddress.FromBytes(data.Slice(6, 6));
        ushort etherType = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(12, 2));

        int l3Offset = 14;
        if (etherType == 0x8100) // 802.1Q VLAN: L3 сдвинут на +4 байта
        {
            if (data.Length < 18) return false;
            etherType = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(16, 2));
            l3Offset = 18;
        }
        if (etherType != 0x0800) return false; // только IPv4

        if (data.Length < l3Offset + 20) return false;
        if ((data[l3Offset] >> 4) != 4) return false; // версия IP == 4
        int ihl = (data[l3Offset] & 0x0F) * 4;
        if (ihl < 20 || data.Length < l3Offset + ihl) return false;

        byte protocol = data[l3Offset + 9];
        if (protocol is not (6 or 17 or 1)) return false;

        uint srcIp = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(l3Offset + 12, 4));
        uint dstIp = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(l3Offset + 16, 4));

        int l4Offset = l3Offset + ihl;
        ushort srcPort = 0, dstPort = 0;
        TcpFlags flags = TcpFlags.None;

        switch (protocol)
        {
            case 6: // TCP
                if (data.Length < l4Offset + 14) return false;
                srcPort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(l4Offset, 2));
                dstPort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(l4Offset + 2, 2));
                flags = (TcpFlags)data[l4Offset + 13];
                break;
            case 17: // UDP
                if (data.Length < l4Offset + 8) return false;
                srcPort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(l4Offset, 2));
                dstPort = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(l4Offset + 2, 2));
                break;
            case 1: // ICMP
                if (data.Length < l4Offset + 4) return false;
                break;
        }

        packet = new ParsedPacket(
            srcMac, dstMac,
            IpAddr.FromIpv4(srcIp), IpAddr.FromIpv4(dstIp),
            srcPort, dstPort, protocol, flags,
            data.Length, timestampTicks);

        return true;
    }
}
