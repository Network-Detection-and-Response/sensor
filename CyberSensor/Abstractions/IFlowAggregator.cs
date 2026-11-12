using CyberSensor.Models;

namespace CyberSensor.Abstractions;

/// <summary>
/// Агрегирует пакеты в сессии (flows) по ключу 5-tuple.
/// Выгрузка сессий производится заполнением переданного списка (без промежуточного канала).
/// </summary>
public interface IFlowAggregator
{
    void ProcessPacket(in ParsedPacket packet);

    int FlushExpired(long nowMs, List<CompletedFlow> into);

    int DrainAll(List<CompletedFlow> into);

    int ActiveFlowCount { get; }

    long TotalFlowsEmitted { get; }
}
