using System.Threading;
using CyberSensor.Models;

namespace CyberSensor.Diagnostics;

/// <summary>Общие счётчики конвейера (для диагностики).</summary>
public sealed class PipelineCounters
{
    private long _channelDropped;
    private long _sentBatches, _sentFlows, _failedBatches;

    /// <summary>Пакетов, вытесненных из канала по DropOldest.</summary>
    public long ChannelDropped => Interlocked.Read(ref _channelDropped);

    /// <summary>Батчей, успешно отправленных на бэкенд.</summary>
    public long SentBatches => Interlocked.Read(ref _sentBatches);

    /// <summary>Flow-записей, успешно отправленных на бэкенд.</summary>
    public long SentFlows => Interlocked.Read(ref _sentFlows);

    /// <summary>Батчей, отправка которых завершилась ошибкой.</summary>
    public long FailedBatches => Interlocked.Read(ref _failedBatches);

    /// <summary>Callback для itemDropped канала (zero-alloc).</summary>
    public void OnChannelDrop(ParsedPacket _) => Interlocked.Increment(ref _channelDropped);

    /// <summary>Фиксирует успешно отправленный батч из <paramref name="flowCount"/> записей.</summary>
    public void IncrementSentBatch(int flowCount)
    {
        Interlocked.Increment(ref _sentBatches);
        Interlocked.Add(ref _sentFlows, flowCount);
    }

    /// <summary>Фиксирует неудачную отправку батча.</summary>
    public void IncrementFailedBatch() => Interlocked.Increment(ref _failedBatches);
}
