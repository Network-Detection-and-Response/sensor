using System.Threading.Channels;
using CyberSensor.Models;

namespace CyberSensor.Abstractions;

/// <summary>
/// Агрегирует пакеты в сессии (flows) по ключу 5-tuple.
/// </summary>
public interface IFlowAggregator
{
    void ProcessPacket(in ParsedPacket packet);

    void FlushExpired(ChannelWriter<CompletedFlow> sink, long nowMs);

    int ActiveFlowCount { get; }

    long TotalFlowsEmitted { get; }
}
