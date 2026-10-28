using CyberSensor.Dto;

namespace CyberSensor.Abstractions;

/// <summary>
/// Отправляет готовые батчи flow-записей на бэкенд по REST.
/// </summary>
public interface IBatchSender
{
    Task SendAsync(FlowBatchRequest batch, CancellationToken ct);
}
