using System.ComponentModel.DataAnnotations;

namespace CyberSensor.Configuration;

/// <summary>
/// Корневая секция настроек сенсора. Биндится из конфигурации по ключу <c>Sensor</c>.
/// </summary>
public sealed class SensorOptions
{
    public const string SectionName = "Sensor";

    [Required(AllowEmptyStrings = false)]
    [RegularExpression("^[a-z0-9_][a-z0-9_\\-]{0,63}$", ErrorMessage = "SensorId должен быть в snake_case: только латиница в нижнем регистре, цифры, '_' и '-'.")]
    public string SensorId { get; set; } = string.Empty;

    /// <summary>Имя/фрагмент описания интерфейса для поиска. Пустая строка — выбор по <see cref="NetworkInterfaceIndex"/>.</summary>
    public string NetworkInterfaceName { get; set; } = string.Empty;

    [Range(0, int.MaxValue)]
    public int NetworkInterfaceIndex { get; set; }

    public string CaptureFilter { get; set; } = "ip";

    [Range(68, 262144)]
    public int Snaplen { get; set; } = 65536;

    public bool PromiscuousMode { get; set; } = true;

    [Range(1, int.MaxValue)]
    public int ReadTimeoutMilliseconds { get; set; } = 1000;

    public RateLimiterOptions RateLimiter { get; set; } = new();

    public AggregatorOptions Aggregator { get; set; } = new();

    public ChannelsOptions Channels { get; set; } = new();

    public BatchOptions Batch { get; set; } = new();

    public BackendOptions Backend { get; set; } = new();
}

public sealed class RateLimiterOptions
{
    public RateLimiterMode Mode { get; set; } = RateLimiterMode.TokenBucket;

    [Range(1, int.MaxValue)]
    public int PermitsPerSecondPerSourceIp { get; set; } = 4000;

    [Range(1, int.MaxValue)]
    public int BurstPerSourceIp { get; set; } = 4000;

    /// <summary>Глобальный лимит пакетов/с (0 — без ограничения).</summary>
    [Range(0, int.MaxValue)]
    public int GlobalPermitsPerSecond { get; set; } = 0;
}

public enum RateLimiterMode
{
    TokenBucket = 0,
    SlidingWindow = 1,
}

public sealed class AggregatorOptions
{
    [Range(1, int.MaxValue)]
    public int FlowTableCapacity { get; set; } = 65536;

    public TimeSpan FlowIdleTimeout { get; set; } = TimeSpan.FromSeconds(30);

    public TimeSpan FlowHardTimeout { get; set; } = TimeSpan.FromMinutes(5);

    public bool IncludeMacAddresses { get; set; } = true;
}

public sealed class ChannelsOptions
{
    [Range(1, int.MaxValue)]
    public int PacketChannelCapacity { get; set; } = 65536;

    public ChannelFullMode PacketChannelFullMode { get; set; } = ChannelFullMode.DropOldest;

    [Range(1, int.MaxValue)]
    public int FlowChannelCapacity { get; set; } = 16384;

    public ChannelFullMode FlowChannelFullMode { get; set; } = ChannelFullMode.Wait;
}

public enum ChannelFullMode
{
    Wait = 0,
    DropOldest = 1,
    DropNewest = 2,
    DropWrite = 3,
}

public sealed class BatchOptions
{
    [Range(1, 10_000)]
    public int MaxBatchSize { get; set; } = 500;

    public TimeSpan FlushInterval { get; set; } = TimeSpan.FromSeconds(5);
}

public sealed class BackendOptions
{
    [Required(AllowEmptyStrings = false, ErrorMessage = "Backend.BaseUrl обязателен.")]
    [Url(ErrorMessage = "Backend.BaseUrl должен быть корректным абсолютным HTTP/HTTPS URL.")]
    public string BaseUrl { get; set; } = "http://localhost:5000";

    public string FlowsEndpoint { get; set; } = "/api/flows";

    public string? ApiKey { get; set; }

    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

    [Range(0, int.MaxValue)]
    public int MaxRetries { get; set; } = 3;
}
