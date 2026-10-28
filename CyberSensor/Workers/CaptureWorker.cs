using System.Threading.Channels;
using CyberSensor.Abstractions;
using CyberSensor.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CyberSensor.Workers;

/// <summary>
/// Воркер перехвата трафика. Запускает цикл захвата и пишет метаданные пакетов в канал.
/// </summary>
public sealed class CaptureWorker : BackgroundService
{
    private readonly ILogger<CaptureWorker> _logger;
    private readonly ICaptureService _captureService;
    private readonly Channel<PacketMeta> _packetChannel;

    public CaptureWorker(
        ILogger<CaptureWorker> logger,
        ICaptureService captureService,
        Channel<PacketMeta> packetChannel)
    {
        _logger = logger;
        _captureService = captureService;
        _packetChannel = packetChannel;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("CaptureWorker запущен.");

        try
        {
            await _captureService.StartAsync(_packetChannel.Writer, stoppingToken);
        }
        finally
        {
            await _captureService.StopAsync(CancellationToken.None);
            _logger.LogInformation("CaptureWorker остановлен.");
        }
    }
}
