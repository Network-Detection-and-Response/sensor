namespace CyberSensor.Models;

/// <summary>
/// MAC-адрес (6 байт) без аллокаций.
/// </summary>
public readonly struct MacAddress : IEquatable<MacAddress>
{
    public readonly byte B0;
    public readonly byte B1;
    public readonly byte B2;
    public readonly byte B3;
    public readonly byte B4;
    public readonly byte B5;

    public static readonly MacAddress Empty = default;

    public MacAddress(byte b0, byte b1, byte b2, byte b3, byte b4, byte b5)
    {
        B0 = b0;
        B1 = b1;
        B2 = b2;
        B3 = b3;
        B4 = b4;
        B5 = b5;
    }

    public static MacAddress FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 6)
        {
            throw new ArgumentException("MacAddress requires exactly 6 bytes.", nameof(bytes));
        }

        return new MacAddress(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    }

    public bool IsEmpty => (B0 | B1 | B2 | B3 | B4 | B5) == 0;

    public bool Equals(MacAddress other) =>
        B0 == other.B0 && B1 == other.B1 && B2 == other.B2 &&
        B3 == other.B3 && B4 == other.B4 && B5 == other.B5;

    public override bool Equals(object? obj) => obj is MacAddress other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(B0, B1, B2, B3, B4, B5);

    public static bool operator ==(MacAddress left, MacAddress right) => left.Equals(right);

    public static bool operator !=(MacAddress left, MacAddress right) => !left.Equals(right);

    public override string ToString() => $"{B0:X2}:{B1:X2}:{B2:X2}:{B3:X2}:{B4:X2}:{B5:X2}";
}
