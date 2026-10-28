using CyberSensor.Abstractions;
using CyberSensor.Configuration;
using CyberSensor.Dto;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CyberSensor.Sending;

/// <summary>
/// Отправка батчей flow-записей на бэкенд по HTTP. Заглушка — логика в следующих шагах.
/// </summary>
public sealed class HttpBatchSender : IBatchSender
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<HttpBatchSender> _logger;
    private readonly string _flowsEndpoint;

    public HttpBatchSender(HttpClient httpClient, ILogger<HttpBatchSender> logger, IOptions<SensorOptions> options)
    {
        _httpClient = httpClient;
        _logger = logger;
        _flowsEndpoint = options.Value.Backend.FlowsEndpoint;
    }

    public Task SendAsync(FlowBatchRequest batch, CancellationToken ct)
    {
        _logger.LogWarning(
            "HttpBatchSender.SendAsync is not implemented yet. BaseAddress={BaseAddress} FlowsEndpoint={FlowsEndpoint}",
            _httpClient.BaseAddress,
            _flowsEndpoint);

        // TODO(Шаг 1.3): реальная отправка по _flowsEndpoint + ретраи на основе Backend.MaxRetries.
        throw new NotImplementedException();
    }
}
