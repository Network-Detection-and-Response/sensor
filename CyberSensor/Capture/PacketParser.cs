using CyberSensor.Models;

namespace CyberSensor.Capture;

/// <summary>
/// Парсинг кадра (L2/L3/L4) в <see cref="PacketMeta"/> без аллокаций. Заглушка.
/// </summary>
public static class PacketParser
{
    /// <summary>
    /// Пытается разобрать кадр. Реализация парсинга — в следующих шагах.
    /// </summary>
    public static bool TryParse(ReadOnlySpan<byte> linkLayerData, out PacketMeta packet)
    {
        packet = default;
        return false;
    }
}
