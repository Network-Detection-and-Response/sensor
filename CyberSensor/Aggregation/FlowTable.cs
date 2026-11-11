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

    /// <summary>Заготовка для Шага 2.3: вытеснение истёкших сессий в список на экспорт.</summary>
    public void RemoveExpired(long nowMs, List<CompletedFlow> into)
    {
        // TODO(Шаг 2.3): обход _flows, сравнение LastSeenMs/FirstSeenMs с nowMs,
        // удаление истёкших сессий и заполнение `into` (без аллокаций на каждый flow).
    }
}
