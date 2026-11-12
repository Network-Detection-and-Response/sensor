using System.Text.Json.Serialization;

namespace CyberSensor.Dto;

/// <summary>
/// Батч flow-записей, отправляемый на бэкенд одним POST-запросом.
/// </summary>
public sealed record FlowBatchRequest
{
    [JsonPropertyName("sensor_id")] public required string SensorId { get; init; }
    [JsonPropertyName("timestamp")] public required string Timestamp { get; init; }
    [JsonPropertyName("flows")] public required IReadOnlyList<FlowDto> Flows { get; init; }
}
