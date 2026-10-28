using System.Threading.Channels;
using CyberSensor.Abstractions;
using CyberSensor.Configuration;
using CyberSensor.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SharpPcap;

namespace CyberSensor.Capture;

/// <summary>
/// Реализация перехвата трафика на базе SharpPcap (Npcap).
/// Цикл захвата — блокирующий (<see cref="ILiveDevice.GetNextPacket"/>) и работает на фоновом
/// потоке; hot path не содержит аллокаций (span напрямую указывает на буфер pcap).
/// </summary>
public sealed class PcapCaptureService : ICaptureService
{
    private readonly ILogger<PcapCaptureService> _logger;
    private readonly INetworkDeviceProvider _deviceProvider;
    private readonly SensorOptions _options;
    private readonly object _gate = new();
    private CancellationTokenSource? _cts;
    private Task? _captureTask;
    private int _running;

    /// <summary>Задержка после ошибки чтения драйвера (не-горячая ветка, R4).</summary>
    private const int ErrorBackoffMs = 100;

    public PcapCaptureService(
        ILogger<PcapCaptureService> logger,
        INetworkDeviceProvider deviceProvider,
        IOptions<SensorOptions> options)
    {
        _logger = logger;
        _deviceProvider = deviceProvider;
        _options = options.Value;
    }

    public Task StartAsync(ChannelWriter<PacketMeta> sink, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(sink);

        if (Interlocked.CompareExchange(ref _running, 1, 0) != 0)
        {
            throw new InvalidOperationException("Перехват уже запущен.");
        }

        // Внутренний CTS: отмена внешнего токена или вызов StopAsync() завершает цикл
        // (ReadTimeout-поллинг + проверка ct на каждой итерации).
        var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task loop = Task.Run(() => CaptureLoop(sink, cts.Token), CancellationToken.None);

        lock (_gate)
        {
            _cts = cts;
            _captureTask = loop;
        }

        // Возвращаем задачу цикла: вызывающий код (CaptureWorker) ожидает её завершения,
        // после чего безопасно вызывает StopAsync.
        return loop;
    }

    public async Task StopAsync(CancellationToken ct)
    {
        CancellationTokenSource? cts;
        Task? loop;
        lock (_gate)
        {
            cts = _cts;
            loop = _captureTask;
        }

        // 1) Отменяем цикл захвата.
        cts?.Cancel();

        // 2) Дожидаемся полного выхода из GetNextPacket и закрытия устройства в finally цикла.
        //    Устройство открывается и закрывается строго внутри CaptureLoop (одна нить), поэтому
        //    Close()/Dispose() устройства никогда не вызываются отсюда, пока цикл ещё жив (R1).
        if (loop is not null)
        {
            try
            {
                await loop.WaitAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Внешняя отмена StopAsync: форсированно не завершаем. Цикл всё равно увидит
                // отмену связанного CTS и сам закроет устройство в собственном finally.
            }
            catch (Exception ex)
            {
                // Ошибка цикла уже залогирована/проброшена через StartAsync; здесь повторно
                // не кидаем, чтобы StopAsync оставался идемпотентным и не маскировал исходную ошибку.
                _logger.LogDebug(ex, "Цикл перехвата завершился с ошибкой (уже обработано в CaptureLoop).");
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync(CancellationToken.None).ConfigureAwait(false);

        CancellationTokenSource? cts;
        lock (_gate)
        {
            cts = _cts;
            _cts = null;
        }

        cts?.Dispose();
    }

    private void CaptureLoop(ChannelWriter<PacketMeta> sink, CancellationToken ct)
    {
        // Флаг защищает от вызова Close() на устройстве, которое не удалось открыть (R3):
        // устанавливается ТОЛЬКО после успешного device.Open(...).
        bool isOpened = false;
        ILiveDevice? device = null;

        try
        {
            device = _deviceProvider.Resolve(ct);

            device.Open(new DeviceConfiguration
            {
                Mode = _options.PromiscuousMode ? DeviceModes.Promiscuous : DeviceModes.None,
                ReadTimeout = _options.ReadTimeoutMilliseconds,
                Snaplen = _options.Snaplen,
            });

            // Флаг ставится сразу после успешного Open(): если Open() выбросил исключение,
            // isOpened остаётся false и finally не вызовет Close() на неоткрытом устройстве (R3).
            // Если же Open() прошёл, но фильтр ниже не установился — устройство всё равно
            // нужно закрыть (иначе утечка дескриптора).
            isOpened = true;

            if (!string.IsNullOrWhiteSpace(_options.CaptureFilter))
            {
                device.Filter = _options.CaptureFilter;
            }

            _logger.LogInformation(
                "Устройство открыто: Name={Name} | LinkType={LinkType} | Snaplen={Snaplen} | Promiscuous={Promiscuous} | Filter={Filter}",
                device.Name,
                device.LinkType,
                _options.Snaplen,
                _options.PromiscuousMode,
                _options.CaptureFilter);

            // Отмена в foreground-режиме: GetNextPacket возвращается по ReadTimeout, затем на
            // каждой итерации проверяется ct. Никаких StopCapture() из внешних колбэков/ct.Register
            // не используется (R2) — это небезопасно при конкуренции с активным чтением.
            while (!ct.IsCancellationRequested)
            {
                GetPacketStatus status = device.GetNextPacket(out PacketCapture capture);

                if (status == GetPacketStatus.PacketRead)
                {
                    // Zero-alloc: span напрямую указывает на буфер pcap, копирования данных нет.
                    ReadOnlySpan<byte> data = capture.Data;

                    // TODO(шаг парсинга): PacketParser.TryParse(data, out PacketMeta meta)
                    //                   → sink.TryWrite(meta) (без аллокаций).
                    // На текущем шаге реальный разбор пакета в PacketMeta не выполняется.
                    _ = data;
                }
                else if (status == GetPacketStatus.Error)
                {
                    // Ошибка драйвера/чтения. Логируем (редкая, не-горячая ветка) и делаем паузу
                    // с учётом отмены, чтобы не упасть и не войти в busy-spin (R4).
                    _logger.LogWarning(
                        "Ошибка чтения пакета с устройства {Name}: {LastError}. Повтор через {Backoff} мс.",
                        device.Name,
                        device.LastError,
                        ErrorBackoffMs);

                    // При отмене Task.Delay бросает OperationCanceledException, который ловит
                    // внешний catch как штатную остановку.
                    Task.Delay(ErrorBackoffMs, ct).GetAwaiter().GetResult();
                }
                else if (status == GetPacketStatus.NoRemainingPackets)
                {
                    // Для live-устройства NoRemainingPackets (PCAP_ERROR_BREAK) не возникает;
                    // для savefile-режима отладки завершаем цикл, чтобы предотвратить busy-spin (R7).
                    _logger.LogInformation("Достигнут конец захвата (NoRemainingPackets).");
                    break;
                }
                // GetPacketStatus.ReadTimeout → штатный таймаут чтения, продолжаем поллинг отмены.
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Штатная остановка по запросу отмены.
        }
        catch (Exception ex) when (ex is not DeviceNotFoundException and not NpcapUnavailableException)
        {
            _logger.LogError(ex, "Необработанная ошибка в цикле перехвата.");
        }
        finally
        {
            Interlocked.Exchange(ref _running, 0);

            // Идемпотентное освобождение: устройство закрывается ровно один раз и только если
            // оно было реально открыто (isOpened), т.е. без double-dispose и без Close на
            // неоткрытом устройстве.
            if (isOpened && device is not null)
            {
                CloseDevice(device);
            }
        }
    }

    /// <summary>
    /// Останавливает фоновый захват (если был запущен) и закрывает дескриптор устройства.
    /// Вызывается только из <see cref="CaptureLoop"/> после полного выхода из чтения.
    /// </summary>
    private void CloseDevice(ILiveDevice device)
    {
        try
        {
            if (device.Started)
            {
                device.StopCapture();
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "StopCapture завершился с ошибкой (проигнорировано).");
        }

        try
        {
            device.Close();
            _logger.LogInformation("Устройство закрыто: {Name}", device.Name);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Close завершился с ошибкой (проигнорировано).");
        }
    }
}
