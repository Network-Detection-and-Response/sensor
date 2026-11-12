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
    private readonly PipelineState _pipeline;

    public AggregationWorker(
        ILogger<AggregationWorker> logger,
        Channel<ParsedPacket> packetChannel,
        IFlowAggregator flowAggregator,
        PipelineCounters counters,
        PipelineState pipeline)
    {
        _logger = logger;
        _packetReader = packetChannel.Reader;
        _flowAggregator = flowAggregator;
        _counters = counters;
        _pipeline = pipeline;
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
        finally
        {
            // Дочитываем остатки (могли остаться при отмене токена) — неблокирующе.
            while (_packetReader.TryRead(out ParsedPacket packet))
            {
                _flowAggregator.ProcessPacket(in packet);
            }
            // Сигнализируем диспетчеру: агрегация завершена, можно делать DrainAll.
            _pipeline.CompleteAggregation();
            _logger.LogInformation("AggregationWorker остановлен.");
        }
    }
}
