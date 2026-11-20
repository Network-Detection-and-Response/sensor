using System.Globalization;
using CyberSensor.Abstractions;
using CyberSensor.Configuration;
using CyberSensor.Diagnostics;
using CyberSensor.Dto;
using CyberSensor.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberSensor.Workers;

/// <summary>
/// Воркер периодического сброса и отправки flow-записей на бэкенд.
/// Объединяет flush (истёкшие сессии) + batch + отправку, чтобы финальный drain
/// при остановке не терялся из-за порядка остановки hosted-сервисов.
/// </summary>
public sealed class BatchDispatcherWorker : BackgroundService
{
    private readonly ILogger<BatchDispatcherWorker> _logger;
    private readonly IFlowAggregator _flowAggregator;
    private readonly IDroppedFloodAggregator _droppedFloodAggregator;
    private readonly IBatchSender _batchSender;
    private readonly PipelineCounters _counters;
    private readonly PipelineState _pipeline;
    private readonly string _sensorId;
    private readonly int _maxBatchSize;
    private readonly TimeSpan _flushInterval;
    private readonly List<CompletedFlow> _buffer = new(256);

    public BatchDispatcherWorker(
        ILogger<BatchDispatcherWorker> logger,
        IFlowAggregator flowAggregator,
        IDroppedFloodAggregator droppedFloodAggregator,
        IBatchSender batchSender,
        PipelineCounters counters,
        PipelineState pipeline,
        IOptions<SensorOptions> options)
    {
        _logger = logger;
        _flowAggregator = flowAggregator;
        _droppedFloodAggregator = droppedFloodAggregator;
        _batchSender = batchSender;
        _counters = counters;
        _pipeline = pipeline;
        _sensorId = options.Value.SensorId;
        _maxBatchSize = options.Value.Batch.MaxBatchSize;
        _flushInterval = options.Value.Batch.FlushInterval;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("BatchDispatcherWorker запущен.");
        using var timer = new PeriodicTimer(_flushInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                int flushed = _flowAggregator.FlushExpired(nowMs, _buffer);
                int dropped = _droppedFloodAggregator.DrainSummaries(_buffer);

                if (flushed + dropped > 0)
                {
                    await SendBufferAsync(stoppingToken).ConfigureAwait(false);
                    _buffer.Clear();
                }

                if (dropped > 0)
                {
                    _counters.AddDroppedSummariesSent(dropped);
                    _logger.LogWarning(
                        "Заблокированный флуд за окно: {Sources} источников (сводок). Отброшено пакетов всего: {Dropped}.",
                        dropped, _counters.RateLimited);
                }
                _logger.LogInformation(
                    "Сброс: выгружено {Flushed} | Отправлено батчей {SentBatches} / flows {SentFlows} | Ошибок {FailedBatches}",
                    flushed, _counters.SentBatches, _counters.SentFlows, _counters.FailedBatches);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally
        {
            // Ждём, пока AggregationWorker дочитает все пакеты (иначе DrainAll недосчитается
            // сессий, добавленных конкурентно при параллельной остановке hosted-сервисов).
            try
            {
                await _pipeline.AggregationCompleted.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                _logger.LogWarning("Таймаут ожидания завершения агрегации — выполняем DrainAll без полной гарантии.");
            }

            _flowAggregator.DrainAll(_buffer);
            _droppedFloodAggregator.DrainSummaries(_buffer);
            if (_buffer.Count > 0)
            {
                using var finalCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                try { await SendBufferAsync(finalCts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException)
                {
                    _logger.LogWarning("Финальный сброс прерван по таймауту 5 с — не отправлено {Count} сессий.", _buffer.Count);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Ошибка финального сброса сессий.");
                }
                _buffer.Clear();
            }
            _logger.LogInformation("BatchDispatcherWorker остановлен.");
        }
    }

    private async Task SendBufferAsync(CancellationToken ct)
    {
        for (int start = 0; start < _buffer.Count; start += _maxBatchSize)
        {
            int count = Math.Min(_maxBatchSize, _buffer.Count - start);
            await _batchSender.SendAsync(BuildBatch(start, count), ct).ConfigureAwait(false);
        }
    }

    private FlowBatchRequest BuildBatch(int start, int count)
    {
        var flows = new List<FlowDto>(count);
        for (int i = start; i < start + count; i++)
            flows.Add(MapFlow(_buffer[i]));
        return new FlowBatchRequest
        {
            SensorId = _sensorId,
            Timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            Flows = flows,
        };
    }

    private static FlowDto MapFlow(in CompletedFlow flow)
    {
        FlowKey key = flow.Key;
        FlowMetrics m = flow.Metrics;
        return new FlowDto
        {
            SrcIp = key.SrcIp.ToString(),
            SrcMac = m.SrcMac.ToString(),
            DstIp = key.DstIp.ToString(),
            DstMac = m.DstMac.ToString(),
            SrcPort = key.SrcPort,
            DstPort = key.DstPort,
            Protocol = ProtocolName(key.Protocol),
            DurationMs = m.DurationMs,
            TotalPackets = m.TotalPackets,
            TotalBytes = m.TotalBytes,
            TcpFlags = new TcpFlagsDto { Syn = m.SynCount, Ack = m.AckCount, Rst = m.RstCount },
        };
    }

    private static string ProtocolName(byte protocol) => protocol switch
    {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        _ => protocol.ToString(),
    };
}
