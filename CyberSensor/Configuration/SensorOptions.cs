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

    /// <summary>Логировать отдельные пакеты (троттлинг ~5/с). Только для отладки парсера; по умолчанию выключено.</summary>
    public bool LogPacketDetail { get; set; }

    public RateLimiterOptions RateLimiter { get; set; } = new();

    public AggregatorOptions Aggregator { get; set; } = new();

    public ChannelsOptions Channels { get; set; } = new();

    public BatchOptions Batch { get; set; } = new();

    public BackendOptions Backend { get; set; } = new();
}

public sealed class RateLimiterOptions
{
    [Range(1, int.MaxValue)]
    public int MaxPacketsPerSecondPerIp { get; set; } = 3000;

    [Range(1, int.MaxValue)]
    public int MaxTrackedIps { get; set; } = 65536;

    public bool RateLimiterEnabled { get; set; } = true;
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
    public int PacketChannelCapacity { get; set; } = 50000;
}

public sealed class BatchOptions
{
    [Range(1, 10_000)]
    public int MaxBatchSize { get; set; } = 500;

    public TimeSpan FlushInterval { get; set; } = TimeSpan.FromSeconds(3);
}

public sealed class BackendOptions
{
    [Required(AllowEmptyStrings = false, ErrorMessage = "Backend.BaseUrl обязателен.")]
    [Url(ErrorMessage = "Backend.BaseUrl должен быть корректным абсолютным HTTP/HTTPS URL.")]
    public string BaseUrl { get; set; } = "http://localhost:8080";

    public string FlowsEndpoint { get; set; } = "/api/v1/flows";

    [Required(AllowEmptyStrings = false, ErrorMessage = "Backend.ApiKey обязателен.")]
    public string? ApiKey { get; set; }

    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);
}
