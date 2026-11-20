using CyberSensor.Models;

namespace CyberSensor.Abstractions;

/// <summary>Агрегирует телеметрию отброшенных rate limiter'ом пакетов в сводку по SrcIp.</summary>
public interface IDroppedFloodAggregator
{
    void RecordDropped(in ParsedPacket packet);
    int DrainSummaries(List<CompletedFlow> destination);
}
