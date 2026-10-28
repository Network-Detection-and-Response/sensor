using System.Net.NetworkInformation;
using CyberSensor.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SharpPcap;
using SharpPcap.LibPcap;

namespace CyberSensor.Capture;

/// <summary>
/// Реализация выбора сетевого интерфейса на базе <see cref="CaptureDeviceList.Instance"/>.
/// Правила выбора (fail-fast):
/// <list type="number">
/// <item>Всегда логировать нумерованный список всех устройств.</item>
/// <item>Если <see cref="SensorOptions.NetworkInterfaceName"/> непустой — искать регистронезависимое
/// вхождение строки в <c>Name</c> или <c>Description</c>.</item>
/// <item>Иначе — выбрать устройство по <see cref="SensorOptions.NetworkInterfaceIndex"/>.</item>
/// </list>
/// </summary>
public sealed class NetworkDeviceProvider : INetworkDeviceProvider
{
    private readonly ILogger<NetworkDeviceProvider> _logger;
    private readonly SensorOptions _options;

    public NetworkDeviceProvider(ILogger<NetworkDeviceProvider> logger, IOptions<SensorOptions> options)
    {
        _logger = logger;
        _options = options.Value;
    }

    public ILiveDevice Resolve(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        CaptureDeviceList devices;
        try
        {
            devices = CaptureDeviceList.Instance;
        }
        catch (PcapException ex)
        {
            _logger.LogCritical(ex, "Ошибка драйвера Npcap при получении списка интерфейсов.");
            throw new NpcapUnavailableException(
                "Не удалось получить список сетевых интерфейсов: ошибка драйвера Npcap. " +
                "Убедитесь, что Npcap установлен (https://npcap.com) и приложение запущено от имени администратора.",
                ex);
        }
        catch (DllNotFoundException ex)
        {
            _logger.LogCritical(ex, "Драйвер Npcap не найден (отсутствует wpcap.dll / Packet.dll).");
            throw new NpcapUnavailableException(
                "Драйвер Npcap не найден (отсутствует wpcap.dll / Packet.dll). " +
                "Установите Npcap (https://npcap.com) и запустите приложение от имени администратора.",
                ex);
        }
        catch (TypeInitializationException ex)
        {
            _logger.LogCritical(ex, "Не удалось инициализировать нативную библиотеку Npcap.");
            throw new NpcapUnavailableException(
                "Не удалось инициализировать нативную библиотеку Npcap. " +
                "Установите Npcap (https://npcap.com) и запустите приложение от имени администратора.",
                ex);
        }
        catch (BadImageFormatException ex)
        {
            _logger.LogCritical(
                ex,
                "Несовпадение разрядности Npcap и процесса (BadImageFormat). " +
                "Установите Npcap той же разрядности, что и процесс (x64), либо соберите приложение под x86.");
            throw new NpcapUnavailableException(
                "Несовпадение разрядности Npcap и процесса. Установите Npcap той же разрядности, " +
                "что и процесс (x64), либо соберите приложение под x86 (https://npcap.com).",
                ex);
        }

        if (devices.Count == 0)
        {
            _logger.LogCritical(
                "Не обнаружено ни одного сетевого интерфейса. " +
                "Убедитесь, что Npcap установлен и приложение запущено от имени администратора.");
            throw new DeviceNotFoundException("Не обнаружено ни одного сетевого интерфейса.");
        }

        _logger.LogInformation("Обнаружено {Count} сетевых интерфейсов", devices.Count);
        for (int i = 0; i < devices.Count; i++)
        {
            var device = devices[i];
            _logger.LogInformation(
                "#{Index}: Name={Name} | Description={Description} | MAC={Mac} | Addresses={Addresses}",
                i,
                device.Name,
                device.Description,
                FormatMac(device.MacAddress),
                FormatAddresses(device));
        }

        ILiveDevice selected = SelectDevice(devices);
        int selectedIndex = devices.IndexOf(selected);

        _logger.LogInformation(
            "Выбран интерфейс: #{Index} Name={Name} | Description={Description}",
            selectedIndex,
            selected.Name,
            selected.Description);

        return selected;
    }

    private ILiveDevice SelectDevice(CaptureDeviceList devices)
    {
        string name = _options.NetworkInterfaceName;
        if (!string.IsNullOrWhiteSpace(name))
        {
            foreach (var device in devices)
            {
                if (ContainsIgnoreCase(device.Name, name) || ContainsIgnoreCase(device.Description, name))
                {
                    return device;
                }
            }

            _logger.LogCritical(
                "Интерфейс по имени '{Requested}' не найден. Доступные имена: {Available}",
                name,
                string.Join(", ", devices.Select(d => d.Name)));
            throw new DeviceNotFoundException($"Интерфейс по имени '{name}' не найден.");
        }

        int index = _options.NetworkInterfaceIndex;
        if (index < 0 || index >= devices.Count)
        {
            _logger.LogCritical(
                "Индекс интерфейса {Index} вне допустимого диапазона [0, {Max}]. Доступные имена: {Available}",
                index,
                devices.Count - 1,
                string.Join(", ", devices.Select(d => d.Name)));
            throw new DeviceNotFoundException(
                $"Индекс интерфейса {index} вне допустимого диапазона [0, {devices.Count - 1}].");
        }

        return devices[index];
    }

    private static bool ContainsIgnoreCase(string? source, string value)
        => source is not null && source.Contains(value, StringComparison.OrdinalIgnoreCase);

    private static string FormatMac(PhysicalAddress? mac)
        => mac is null || mac.Equals(PhysicalAddress.None) ? "(none)" : mac.ToString();

    private static string FormatAddresses(ILiveDevice device)
    {
        if (device is not LibPcapLiveDevice liveDevice || liveDevice.Addresses.Count == 0)
        {
            return "(none)";
        }

        return string.Join(", ", liveDevice.Addresses);
    }
}
