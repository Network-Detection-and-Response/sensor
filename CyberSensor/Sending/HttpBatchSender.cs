using System.Net.Http;
using System.Text;
using System.Text.Json;
using CyberSensor.Abstractions;
using CyberSensor.Configuration;
using CyberSensor.Diagnostics;
using CyberSensor.Dto;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberSensor.Sending;

/// <summary>
/// Отправка батчей flow-записей на бэкенд по HTTP (POST /api/v1/flows).
/// Никогда не бросает исключений на сбоях бэкенда — сенсор не останавливается.
/// </summary>
public sealed class HttpBatchSender : IBatchSender
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<HttpBatchSender> _logger;
    private readonly PipelineCounters _counters;
    private readonly string _flowsEndpoint;

    public HttpBatchSender(
        HttpClient httpClient,
        ILogger<HttpBatchSender> logger,
        PipelineCounters counters,
        IOptions<SensorOptions> options)
    {
        _httpClient = httpClient;
        _logger = logger;
        _counters = counters;
        _flowsEndpoint = options.Value.Backend.FlowsEndpoint;
    }

    public async Task SendAsync(FlowBatchRequest batch, CancellationToken ct)
    {
        try
        {
            string json = JsonSerializer.Serialize(batch, SensorJsonContext.Default.FlowBatchRequest);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var response = await _httpClient.PostAsync(_flowsEndpoint, content, ct).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                _counters.IncrementSentBatch(batch.Flows.Count);
                _logger.LogInformation("Батч отправлен: {Count} flows (HTTP {(int)response.StatusCode}).", batch.Flows.Count, (int)response.StatusCode);
            }
            else
            {
                _counters.IncrementFailedBatch();
                _logger.LogWarning("Бэкенд вернул HTTP {(int)response.StatusCode} при отправке батча ({Count} flows).", (int)response.StatusCode, batch.Flows.Count);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // штатная остановка — не считаем ошибкой отправки
        }
        catch (HttpRequestException ex)
        {
            _counters.IncrementFailedBatch();
            _logger.LogWarning(ex, "HTTP-ошибка отправки батча ({Count} flows): {Reason}.", batch.Flows.Count, ex.Message);
        }
        catch (TaskCanceledException ex) // таймаут (ct не отменён)
        {
            _counters.IncrementFailedBatch();
            _logger.LogWarning(ex, "Таймаут отправки батча ({Count} flows).", batch.Flows.Count);
        }
    }
}
