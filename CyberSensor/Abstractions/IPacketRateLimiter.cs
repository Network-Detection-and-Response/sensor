using System.Threading.RateLimiting;
using CyberSensor.Models;

namespace CyberSensor.Abstractions;

/// <summary>
/// Ограничитель интенсивности на уровне пакетов (не путать с System.Threading.RateLimiting).
/// Лимитирование ведётся per-IP: разрешение на пропуск пакета запрашивается по адресу источника.
/// </summary>
public interface IPacketRateLimiter
{
    ValueTask<bool> TryAcquireAsync(IpAddr sourceIp, CancellationToken ct = default);

    RateLimiterStatistics? GetStatistics();
}
