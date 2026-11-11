using System.Threading.Channels;
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

    public FlowAggregator(ILogger<FlowAggregator> logger, IOptions<SensorOptions> options)
    {
        _logger = logger;
        _table = new FlowTable(options.Value.Aggregator.FlowTableCapacity);
    }

    public int ActiveFlowCount => _table.Count;

    public long TotalFlowsEmitted => 0;

    public void ProcessPacket(in ParsedPacket packet)
    {
        long timestampMs = packet.TimestampTicks / TimeSpan.TicksPerMillisecond;
        _table.Process(in packet, timestampMs);
    }

    public void FlushExpired(ChannelWriter<CompletedFlow> sink, long nowMs)
    {
        // TODO(Шаг 2.3): логика экспирации по FlowIdleTimeout/FlowHardTimeout.
        _logger.LogWarning("FlowAggregator.FlushExpired is not implemented yet (Шаг 2.3).");
        throw new NotImplementedException();
    }
}
