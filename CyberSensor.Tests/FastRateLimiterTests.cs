using CyberSensor.Configuration;
using CyberSensor.Models;
using CyberSensor.RateLimiting;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace CyberSensor.Tests;

public sealed class FastRateLimiterTests
{
    private static FastRateLimiter Create(int limit, bool enabled = true, FakeTimeProvider? time = null)
    {
        var opts = Options.Create(new SensorOptions
        {
            RateLimiter = new RateLimiterOptions
            {
                MaxPacketsPerSecondPerIp = limit,
                MaxTrackedIps = 65536,
                RateLimiterEnabled = enabled,
            },
        });
        return new FastRateLimiter(opts, time ?? new FakeTimeProvider(DateTimeOffset.UtcNow));
    }

    [Fact]
    public void AllowsExactlyN_AndRejectsNext()
    {
        var limiter = Create(3);
        IpAddr ip = IpAddr.FromIpv4(0xC0A80101);
        for (int i = 0; i < 3; i++) Assert.True(limiter.IsAllowed(ip));
        Assert.False(limiter.IsAllowed(ip));
    }

    [Fact]
    public void PerIpIsolation()
    {
        var limiter = Create(1);
        IpAddr ipA = IpAddr.FromIpv4(0xC0A80101);
        IpAddr ipB = IpAddr.FromIpv4(0xC0A80102);

        Assert.True(limiter.IsAllowed(ipA));
        Assert.False(limiter.IsAllowed(ipA));
        Assert.True(limiter.IsAllowed(ipB));
    }

    [Fact]
    public void WindowResetsAfterOneSecond()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var limiter = Create(1, time: time);
        IpAddr ipA = IpAddr.FromIpv4(0xC0A80101);

        Assert.True(limiter.IsAllowed(ipA));
        Assert.False(limiter.IsAllowed(ipA));

        time.Advance(TimeSpan.FromSeconds(1));

        Assert.True(limiter.IsAllowed(ipA));
    }

    [Fact]
    public void Disabled_AllowsBeyondLimit()
    {
        var limiter = Create(1, enabled: false);
        IpAddr ipA = IpAddr.FromIpv4(0xC0A80101);

        Assert.True(limiter.IsAllowed(ipA));
        Assert.True(limiter.IsAllowed(ipA));
        Assert.True(limiter.IsAllowed(ipA));
    }
}
