using System.Threading.Channels;
using CyberSensor.Abstractions;
using CyberSensor.Diagnostics;
using CyberSensor.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace CyberSensor.Workers;

/// <summary>
/// Воркер агрегации пакетов в сессии. Вход: Channel&lt;ParsedPacket&gt;, выход: Channel&lt;CompletedFlow&gt;.
/// </summary>
public sealed class AggregationWorker : BackgroundService
{
    private readonly ILogger<AggregationWorker> _logger;
    private readonly ChannelReader<ParsedPacket> _packetReader;
    private readonly IFlowAggregator _flowAggregator;
    private readonly PipelineCounters _counters;

    public AggregationWorker(
        ILogger<AggregationWorker> logger,
        Channel<ParsedPacket> packetChannel,
        IFlowAggregator flowAggregator,
        PipelineCounters counters)
    {
        _logger = logger;
        _packetReader = packetChannel.Reader;
        _flowAggregator = flowAggregator;
        _counters = counters;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("AggregationWorker запущен.");
        long processed = 0;
        long lastStatsTick = Environment.TickCount64;
        try
        {
            while (await _packetReader.WaitToReadAsync(stoppingToken).ConfigureAwait(false))
            {
                while (_packetReader.TryRead(out ParsedPacket packet))
                {
                    _flowAggregator.ProcessPacket(in packet);
                    processed++;
                }

                long now = Environment.TickCount64;
                if (now - lastStatsTick >= 5000)
                {
                    lastStatsTick = now;
                    _logger.LogInformation(
                        "Активных сессий: {Active} | Обработано пакетов: {Processed} | Вытеснено каналом (DropOldest): {Dropped}",
                        _flowAggregator.ActiveFlowCount, processed, _counters.ChannelDropped);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // штатная остановка
        }

        _logger.LogInformation("AggregationWorker остановлен.");
    }
}
