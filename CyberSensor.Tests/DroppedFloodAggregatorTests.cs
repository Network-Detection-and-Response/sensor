using CyberSensor.Aggregation;
using CyberSensor.Configuration;
using CyberSensor.Models;
using Microsoft.Extensions.Options;
using Xunit;

namespace CyberSensor.Tests;

public sealed class DroppedFloodAggregatorTests
{
    private static DroppedFloodAggregator Create(int maxTrackedIps = 65536)
    {
        var opts = Options.Create(new SensorOptions
        {
            RateLimiter = new RateLimiterOptions
            {
                MaxPacketsPerSecondPerIp = 3000,
                MaxTrackedIps = maxTrackedIps,
                RateLimiterEnabled = true,
            },
        });
        return new DroppedFloodAggregator(opts);
    }

    private static ParsedPacket MakePacket(IpAddr srcIp, ushort srcPort, TcpFlags flags = TcpFlags.Syn, int totalBytes = 100, long tsMs = 1000)
        => new(
            MacAddress.Empty, MacAddress.Empty,
            srcIp, IpAddr.FromIpv4(0x0A000005),
            srcPort, 443, 6, flags, totalBytes, tsMs * TimeSpan.TicksPerMillisecond);

    [Fact]
    public void Collapses_ToSingleSummary_WithSrcPortZero()
    {
        var agg = Create();
        IpAddr src = IpAddr.FromIpv4(0xC0A80101);
        for (int i = 0; i < 100; i++)
            agg.RecordDropped(MakePacket(src, (ushort)(1000 + i), tsMs: 1000 + i));

        var list = new List<CompletedFlow>();
        Assert.Equal(1, agg.DrainSummaries(list));

        var flow = Assert.Single(list);
        Assert.Equal(src, flow.Key.SrcIp);
        Assert.Equal((ushort)0, flow.Key.SrcPort);
        Assert.Equal(100L, flow.Metrics.TotalPackets);
        Assert.Equal(10_000L, flow.Metrics.TotalBytes);
        Assert.Equal(100, flow.Metrics.SynCount);
        Assert.Equal(0, flow.Metrics.AckCount);
        Assert.Equal(0, flow.Metrics.RstCount);
        Assert.Equal(99L, flow.Metrics.DurationMs);
    }

    [Fact]
    public void DistinctSources_ProduceSeparateSummaries()
    {
        var agg = Create();
        agg.RecordDropped(MakePacket(IpAddr.FromIpv4(0xC0A80101), 1000));
        agg.RecordDropped(MakePacket(IpAddr.FromIpv4(0xC0A80102), 1000));
        var list = new List<CompletedFlow>();
        Assert.Equal(2, agg.DrainSummaries(list));
    }

    [Fact]
    public void DrainSummaries_ClearsState()
    {
        var agg = Create();
        agg.RecordDropped(MakePacket(IpAddr.FromIpv4(0xC0A80101), 1000));
        var list = new List<CompletedFlow>();
        Assert.Equal(1, agg.DrainSummaries(list));
        Assert.Equal(0, agg.DrainSummaries(list));
    }

    [Fact]
    public void SpoofingProtection_CapsUniqueIps()
    {
        var agg = Create(maxTrackedIps: 2);
        for (int i = 0; i < 10; i++)
            agg.RecordDropped(MakePacket(IpAddr.FromIpv4((uint)(0x0A000000 + i)), 1000));
        var list = new List<CompletedFlow>();
        Assert.Equal(2, agg.DrainSummaries(list));
    }
}
