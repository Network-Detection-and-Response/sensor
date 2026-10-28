using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CyberSensor.Workers;

/// <summary>
/// Воркер агрегации пакетов в сессии. Заглушка — логика в следующих шагах.
/// </summary>
public sealed class AggregationWorker : BackgroundService
{
    private readonly ILogger<AggregationWorker> _logger;

    public AggregationWorker(ILogger<AggregationWorker> logger)
    {
        _logger = logger;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("AggregationWorker started (stub).");
        return Task.CompletedTask;
    }
}
