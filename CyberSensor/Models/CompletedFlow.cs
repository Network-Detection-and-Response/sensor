namespace CyberSensor.Models;

/// <summary>Завершённая сессия: 5-tuple ключ + накопленные метрики. Для экспорта/батчинга.</summary>
public readonly record struct CompletedFlow(FlowKey Key, FlowMetrics Metrics);
