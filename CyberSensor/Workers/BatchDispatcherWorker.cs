using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CyberSensor.Workers;

/// <summary>
/// Воркер батчевой отправки flow-записей на бэкенд. Заглушка — логика в следующих шагах.
/// </summary>
public sealed class BatchDispatcherWorker : BackgroundService
{
    private readonly ILogger<BatchDispatcherWorker> _logger;

    public BatchDispatcherWorker(ILogger<BatchDispatcherWorker> logger)
    {
        _logger = logger;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("BatchDispatcherWorker started (stub).");
        return Task.CompletedTask;
    }
}
