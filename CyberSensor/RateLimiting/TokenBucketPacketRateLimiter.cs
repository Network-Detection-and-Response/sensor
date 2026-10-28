using System.Threading.RateLimiting;
using CyberSensor.Abstractions;
using CyberSensor.Models;
using Microsoft.Extensions.Logging;

namespace CyberSensor.RateLimiting;

/// <summary>
/// Token Bucket ограничитель интенсивности пакетов (per-IP). Заглушка — логика в следующих шагах.
/// </summary>
public sealed class TokenBucketPacketRateLimiter : IPacketRateLimiter
{
    private readonly ILogger<TokenBucketPacketRateLimiter> _logger;

    public TokenBucketPacketRateLimiter(ILogger<TokenBucketPacketRateLimiter> logger)
    {
        _logger = logger;
    }

    public ValueTask<bool> TryAcquireAsync(IpAddr sourceIp, CancellationToken ct = default)
    {
        _logger.LogWarning("TokenBucketPacketRateLimiter.TryAcquireAsync is not implemented yet.");
        throw new NotImplementedException();
    }

    public RateLimiterStatistics? GetStatistics()
    {
        return null;
    }
}
