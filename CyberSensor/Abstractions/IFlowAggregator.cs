using System.Threading.Channels;
using CyberSensor.Models;

namespace CyberSensor.Abstractions;

/// <summary>
/// Агрегирует пакеты в сессии (flows) по ключу 5-tuple.
/// </summary>
public interface IFlowAggregator
{
    void Add(in PacketMeta packet);

    void FlushExpired(ChannelWriter<FlowRecord> sink, long nowUnixMs);

    int ActiveFlowCount { get; }

    long TotalFlowsEmitted { get; }
}
