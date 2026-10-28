using System.Threading.Channels;
using CyberSensor.Abstractions;
using CyberSensor.Models;
using Microsoft.Extensions.Logging;

namespace CyberSensor.Aggregation;

/// <summary>
/// Агрегатор пакетов в сессии. Заглушка — логика в следующих шагах.
/// </summary>
public sealed class FlowAggregator : IFlowAggregator
{
    private readonly ILogger<FlowAggregator> _logger;
    private readonly FlowTable _table = new();

    public FlowAggregator(ILogger<FlowAggregator> logger)
    {
        _logger = logger;
    }

    public int ActiveFlowCount => _table.Count;

    public long TotalFlowsEmitted => 0;

    public void Add(in PacketMeta packet)
    {
        _logger.LogWarning("FlowAggregator.Add is not implemented yet.");
        throw new NotImplementedException();
    }

    public void FlushExpired(ChannelWriter<FlowRecord> sink, long nowUnixMs)
    {
        _logger.LogWarning("FlowAggregator.FlushExpired is not implemented yet.");
        throw new NotImplementedException();
    }
}
