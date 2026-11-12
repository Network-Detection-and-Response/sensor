using System.Threading.Tasks;

namespace CyberSensor.Diagnostics;

/// <summary>Состояние конвейера: сигнал завершения агрегации для корректного финального drain.</summary>
public sealed class PipelineState
{
    private readonly TaskCompletionSource _aggregationCompleted =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Завершается, когда AggregationWorker полностью обработал все пакеты.</summary>
    public Task AggregationCompleted => _aggregationCompleted.Task;

    /// <summary>Сигнализирует завершение агрегации (идемпотентно).</summary>
    public void CompleteAggregation() => _aggregationCompleted.TrySetResult();
}
