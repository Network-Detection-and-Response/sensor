using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;

namespace CyberSensor.Models;

/// <summary>
/// IP-адрес (IPv4 или IPv6) в 16-байтовом представлении без аллокаций.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 16)]
public readonly struct IpAddr : IEquatable<IpAddr>
{
    [FieldOffset(0)]
    public readonly ulong High;

    [FieldOffset(8)]
    public readonly ulong Low;

    public static readonly IpAddr Empty = default;

    public IpAddr(ulong high, ulong low)
    {
        High = high;
        Low = low;
    }

    public static IpAddr FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 16)
        {
            throw new ArgumentException("IpAddr requires exactly 16 bytes.", nameof(bytes));
        }

        ulong high = BinaryPrimitives.ReadUInt64BigEndian(bytes);
        ulong low = BinaryPrimitives.ReadUInt64BigEndian(bytes[8..]);
        return new IpAddr(high, low);
    }

    /// <summary>
    /// Создаёт IpAddr из IPv4-адреса в сетевом порядке байт (big-endian) без аллокаций.
    /// Кодирование — IPv4-mapped IPv6 (::ffff:a.b.c.d): High=0, младшие 32 бита Low = адрес.
    /// </summary>
    public static IpAddr FromIpv4(uint ipv4)
    {
        return new IpAddr(0, 0x0000FFFF00000000UL | ipv4);
    }

    public bool IsEmpty => (High | Low) == 0;

    public bool Equals(IpAddr other) => High == other.High && Low == other.Low;

    public override bool Equals(object? obj) => obj is IpAddr other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(High, Low);

    public static bool operator ==(IpAddr left, IpAddr right) => left.Equals(right);

    public static bool operator !=(IpAddr left, IpAddr right) => !left.Equals(right);

    public override string ToString()
    {
        Span<byte> bytes = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, High);
        BinaryPrimitives.WriteUInt64BigEndian(bytes[8..], Low);
        return new IPAddress(bytes).ToString();
    }
}
