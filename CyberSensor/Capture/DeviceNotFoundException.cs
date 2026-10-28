namespace CyberSensor.Capture;

/// <summary>
/// Доменное исключение: сетевой интерфейс не найден
/// (пустой список устройств, нет совпадения по имени или индекс вне диапазона).
/// </summary>
public sealed class DeviceNotFoundException : Exception
{
    public DeviceNotFoundException(string message)
        : base(message)
    {
    }

    public DeviceNotFoundException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
