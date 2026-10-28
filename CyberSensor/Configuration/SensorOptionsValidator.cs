using Microsoft.Extensions.Options;

namespace CyberSensor.Configuration;

/// <summary>
/// Кросс-полевая валидация <see cref="SensorOptions"/>. Простые правила продублированы здесь
/// (в дополнение к DataAnnotations); проверка выхода индекса за границы фактического списка
/// устройств выполняется на этапе разрешения интерфейса в <c>NetworkDeviceProvider.Resolve</c>,
/// поскольку число устройств неизвестно на этапе биндинга конфигурации.
/// </summary>
public sealed class SensorOptionsValidator : IValidateOptions<SensorOptions>
{
    public ValidateOptionsResult Validate(string? name, SensorOptions options)
    {
        if (options is null)
        {
            return ValidateOptionsResult.Fail("Секция конфигурации 'Sensor' отсутствует.");
        }

        var errors = new List<string>();

        if (options.NetworkInterfaceIndex < 0)
        {
            errors.Add($"'{nameof(SensorOptions.NetworkInterfaceIndex)}' должен быть >= 0.");
        }

        if (options.ReadTimeoutMilliseconds < 1)
        {
            errors.Add($"'{nameof(SensorOptions.ReadTimeoutMilliseconds)}' должен быть >= 1.");
        }

        if (options.Snaplen < 68)
        {
            errors.Add($"'{nameof(SensorOptions.Snaplen)}' должен быть >= 68.");
        }

        if (options.RateLimiter.GlobalPermitsPerSecond < 0)
        {
            errors.Add($"'{nameof(SensorOptions.RateLimiter)}.{nameof(RateLimiterOptions.GlobalPermitsPerSecond)}' должен быть >= 0 (0 — без глобального ограничения).");
        }

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(errors);
    }
}
