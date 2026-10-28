using System.Threading.Channels;
using CyberSensor.Models;

namespace CyberSensor.Abstractions;

/// <summary>
/// Сервис перехвата трафика (L2/L3). Поставляет метаданные пакетов в канал.
/// </summary>
public interface ICaptureService : IAsyncDisposable
{
    Task StartAsync(ChannelWriter<PacketMeta> sink, CancellationToken ct);

    Task StopAsync(CancellationToken ct);
}
