using CyberSensor.Abstractions;
using CyberSensor.Configuration;
using CyberSensor.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberSensor.Aggregation;

/// <summary>
/// Агрегатор пакетов в сессии (flows) по ключу 5-tuple. Хранит активные сессии в <see cref="FlowTable"/>.
/// </summary>
public sealed class FlowAggregator : IFlowAggregator
{
    private readonly ILogger<FlowAggregator> _logger;
    private readonly FlowTable _table;
    private readonly long _idleTimeoutMs;
    private readonly long _activeTimeoutMs;
    private long _totalFlowsEmitted;

    public FlowAggregator(ILogger<FlowAggregator> logger, IOptions<SensorOptions> options)
    {
        _logger = logger;
        var aggregator = options.Value.Aggregator;
        _table = new FlowTable(aggregator.FlowTableCapacity);
        _idleTimeoutMs = (long)aggregator.FlowIdleTimeout.TotalMilliseconds;
        _activeTimeoutMs = (long)aggregator.FlowHardTimeout.TotalMilliseconds;
    }

    public int ActiveFlowCount => _table.Count;

    public long TotalFlowsEmitted => Interlocked.Read(ref _totalFlowsEmitted);

    public void ProcessPacket(in ParsedPacket packet)
    {
        long timestampMs = packet.TimestampTicks / TimeSpan.TicksPerMillisecond;
        _table.Process(in packet, timestampMs);
    }

    public int FlushExpired(long nowMs, List<CompletedFlow> into)
    {
        into.Clear();
        _table.RemoveExpired(nowMs, _idleTimeoutMs, _activeTimeoutMs, into);
        Interlocked.Add(ref _totalFlowsEmitted, into.Count);
        return into.Count;
    }

    public int DrainAll(List<CompletedFlow> into)
    {
        into.Clear();
        _table.DrainAll(into);
        Interlocked.Add(ref _totalFlowsEmitted, into.Count);
        return into.Count;
    }
}
