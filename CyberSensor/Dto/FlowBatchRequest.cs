namespace CyberSensor.Dto;

/// <summary>
/// Батч flow-записей, отправляемый на бэкенд одним POST-запросом.
/// </summary>
public sealed record FlowBatchRequest
{
    public required string SensorId { get; init; }

    public required string BatchId { get; init; }

    public required long CapturedAt { get; init; }

    public required IReadOnlyList<FlowDto> Flows { get; init; }
}
