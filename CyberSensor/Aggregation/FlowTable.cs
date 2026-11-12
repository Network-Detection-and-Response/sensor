using System.Runtime.InteropServices;
using CyberSensor.Models;

namespace CyberSensor.Aggregation;

/// <summary>
/// Хранилище активных flow: Dictionary&lt;FlowKey, FlowMetrics&gt; с предвыделением ёмкости
/// и мутацией метрик по ссылке (CollectionsMarshal) без аллокаций в hot path.
/// </summary>
internal sealed class FlowTable
{
    private readonly Dictionary<FlowKey, FlowMetrics> _flows;
    private readonly object _lock = new();

    public FlowTable(int capacity)
    {
        // Предвыделение: избегает реаллокаций словаря при росте под нагрузкой.
        _flows = new Dictionary<FlowKey, FlowMetrics>(capacity);
    }

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _flows.Count;
            }
        }
    }

    public void Process(in ParsedPacket packet, long timestampMs)
    {
        FlowKey key = FlowKey.FromPacket(in packet);
        lock (_lock)
        {
            ref FlowMetrics entry = ref CollectionsMarshal.GetValueRefOrAddDefault(_flows, key, out bool exists);
            if (exists)
            {
                entry.AddPacket(in packet, timestampMs);
            }
            else
            {
                entry = FlowMetrics.CreateFromFirstPacket(in packet, timestampMs);
            }
        }
    }

    /// <summary>
    /// Вытесняет истёкшие сессии (idle/hard timeout либо TCP RST) в список на экспорт.
    /// </summary>
    public void RemoveExpired(long nowMs, long idleTimeoutMs, long activeTimeoutMs, List<CompletedFlow> into)
    {
        lock (_lock)
        {
            foreach (KeyValuePair<FlowKey, FlowMetrics> kv in _flows)
            {
                FlowMetrics m = kv.Value;
                bool expired = (nowMs - m.LastSeenMs >= idleTimeoutMs)
                            || (nowMs - m.FirstSeenMs >= activeTimeoutMs)
                            || (m.RstCount > 0);
                if (expired) into.Add(new CompletedFlow(kv.Key, m));
            }

            // удаляем после обхода (нельзя модифицировать словарь во время перечисления)
            foreach (CompletedFlow flow in into) _flows.Remove(flow.Key);
        }
    }

    /// <summary>Выгружает все оставшиеся сессии (финальный drain при остановке).</summary>
    public void DrainAll(List<CompletedFlow> into)
    {
        lock (_lock)
        {
            foreach (KeyValuePair<FlowKey, FlowMetrics> kv in _flows)
                into.Add(new CompletedFlow(kv.Key, kv.Value));
            _flows.Clear();
        }
    }
}
