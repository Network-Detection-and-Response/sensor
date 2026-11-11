using System.Threading.Channels;
using CyberSensor.Models;

namespace CyberSensor.Abstractions;

/// <summary>
/// Сервис перехвата трафика (L2/L3). Поставляет разобранные пакеты в канал.
/// </summary>
public interface ICaptureService : IAsyncDisposable
{
    Task StartAsync(ChannelWriter<ParsedPacket> sink, CancellationToken ct);

    Task StopAsync(CancellationToken ct);
}
