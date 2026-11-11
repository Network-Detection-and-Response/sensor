using System.Collections.Concurrent;
using CyberSensor.Abstractions;
using CyberSensor.Configuration;
using CyberSensor.Models;
using Microsoft.Extensions.Options;

namespace CyberSensor.RateLimiting;

/// <summary>
/// Fixed Window Counter ограничитель пакетов per-source-IP (синхронный, без блокировок).
/// Окно — текущая секунда (<see cref="Environment.TickCount64"/> / 1000).
/// </summary>
/// <remarks>
/// Приблизительный Fixed Window: на границе секунды допустимы незначительные гонки
/// (часть пакетов может быть учтена по старому окну). Блокировки отсутствуют осознанно —
/// приоритет производительности hot path. Победитель CAS очищает словарь счётчиков,
/// проигравшие продолжают работать со старым окном до следующей проверки.
/// </remarks>
public sealed class FastRateLimiter : IPacketRateLimiter
{
    private readonly int _limitPerSecond;
    private readonly ConcurrentDictionary<IpAddr, int> _counts = new();
    private long _windowSecond;

    public FastRateLimiter(IOptions<SensorOptions> options)
    {
        _limitPerSecond = options.Value.RateLimiter.PermitsPerSecondPerSourceIp;
        _windowSecond = Environment.TickCount64 / 1000;
    }

    public bool IsAllowed(in IpAddr sourceIp)
    {
        long nowSecond = Environment.TickCount64 / 1000;
        long windowSecond = _windowSecond;

        if (nowSecond != windowSecond)
        {
            // Атомарный сдвиг окна: победитель гонки вызывает Clear() ровно один раз.
            if (Interlocked.CompareExchange(ref _windowSecond, nowSecond, windowSecond) == windowSecond)
            {
                _counts.Clear();
            }
        }

        int count = _counts.AddOrUpdate(sourceIp, 1, static (_, c) => c + 1);
        return count <= _limitPerSecond;
    }
}
