using System.Text.Json.Serialization;

namespace CyberSensor.Dto;

/// <summary>
/// Source-generated JSON-контекст для сериализации DTO без рефлексии.
/// Имена полей заданы явно через <see cref="JsonPropertyNameAttribute"/>, поэтому
/// <c>PropertyNamingPolicy</c> не используется.
/// </summary>
[JsonSourceGenerationOptions(
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(FlowBatchRequest))]
public sealed partial class SensorJsonContext : JsonSerializerContext
{
}
