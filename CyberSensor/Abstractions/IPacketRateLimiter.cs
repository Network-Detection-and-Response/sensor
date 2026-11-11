using CyberSensor.Models;

namespace CyberSensor.Abstractions;

/// <summary>
/// Ограничитель интенсивности пакетов per-source-IP (синхронный, без аллокаций).
/// </summary>
public interface IPacketRateLimiter
{
    bool IsAllowed(in IpAddr sourceIp);
}
