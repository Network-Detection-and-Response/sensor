using SharpPcap;

namespace CyberSensor.Capture;

/// <summary>
/// Поставщик сетевого интерфейса для перехвата. Разрешает конфигурацию
/// (имя или индекс) в конкретное устройство <see cref="ILiveDevice"/>.
/// </summary>
public interface INetworkDeviceProvider
{
    /// <summary>
    /// Находит устройство по правилам выбора (сначала имя, затем индекс) с fail-fast семантикой:
    /// при отсутствии устройства выбрасывает доменное исключение.
    /// </summary>
    ILiveDevice Resolve(CancellationToken ct = default);
}
