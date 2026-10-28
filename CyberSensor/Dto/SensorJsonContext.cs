using System.Text.Json.Serialization;

namespace CyberSensor.Dto;

/// <summary>
/// Source-generated JSON-контекст для сериализации DTO без рефлексии.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(FlowBatchRequest))]
public sealed partial class SensorJsonContext : JsonSerializerContext
{
}
