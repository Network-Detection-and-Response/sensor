using System.Threading;
using CyberSensor.Models;

namespace CyberSensor.Diagnostics;

/// <summary>Общие счётчики конвейера (для диагностики).</summary>
public sealed class PipelineCounters
{
    private long _channelDropped;

    /// <summary>Пакетов, вытесненных из канала по DropOldest.</summary>
    public long ChannelDropped => Interlocked.Read(ref _channelDropped);

    /// <summary>Callback для itemDropped канала (zero-alloc).</summary>
    public void OnChannelDrop(ParsedPacket _) => Interlocked.Increment(ref _channelDropped);
}
