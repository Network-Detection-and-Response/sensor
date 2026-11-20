using System.Collections.Concurrent;
using CyberSensor.Abstractions;
using CyberSensor.Configuration;
using CyberSensor.Models;
using Microsoft.Extensions.Options;

namespace CyberSensor.RateLimiting;

/// <summary>
/// Fixed Window Counter per-source-IP (синхронный, zero-alloc). Окно — 1 секунда через TimeProvider.
/// </summary>
public sealed class FastRateLimiter : IPacketRateLimiter
{
    private readonly TimeProvider _timeProvider;
    private readonly int _limitPerSecond;
    private readonly int _maxTrackedIps;
    private readonly bool _enabled;
    private readonly ConcurrentDictionary<IpAddr, int> _counts = new();
    private long _windowSecond;

    public FastRateLimiter(IOptions<SensorOptions> options, TimeProvider timeProvider)
    {
        var rl = options.Value.RateLimiter;
        _timeProvider = timeProvider;
        _limitPerSecond = rl.MaxPacketsPerSecondPerIp;
        _maxTrackedIps = rl.MaxTrackedIps;
        _enabled = rl.RateLimiterEnabled;
        _windowSecond = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
    }

    public bool IsAllowed(in IpAddr sourceIp)
    {
        if (!_enabled)
        {
            return true;
        }

        long nowSecond = _timeProvider.GetUtcNow().ToUnixTimeSeconds();
        long windowSecond = _windowSecond;
        if (nowSecond != windowSecond)
        {
            // Атомарный сдвиг окна: победитель CAS очищает словарь ровно один раз.
            if (Interlocked.CompareExchange(ref _windowSecond, nowSecond, windowSecond) == windowSecond)
            {
                _counts.Clear();
            }
        }

        // Защита от IP-spoofing: не даём словарю раздуться бесконечно за окно.
        if (_counts.Count >= _maxTrackedIps && !_counts.ContainsKey(sourceIp))
        {
            return false;
        }

        // static-лямбда — без аллокации замыкания на каждый пакет.
        int count = _counts.AddOrUpdate(sourceIp, 1, static (_, c) => c + 1);
        return count <= _limitPerSecond;
    }
}
