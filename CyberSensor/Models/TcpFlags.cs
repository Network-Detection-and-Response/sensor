namespace CyberSensor.Models;

/// <summary>
/// Флаги TCP-заголовка.
/// </summary>
[Flags]
public enum TcpFlags : byte
{
    None = 0,
    Fin = 1 << 0,
    Syn = 1 << 1,
    Rst = 1 << 2,
    Psh = 1 << 3,
    Ack = 1 << 4,
    Urg = 1 << 5,
    Ece = 1 << 6,
    Cwr = 1 << 7,
}
