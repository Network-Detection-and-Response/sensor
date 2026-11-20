using System.Threading.Channels;
using CyberSensor.Abstractions;
using CyberSensor.Configuration;
using CyberSensor.Diagnostics;
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
    private readonly IPacketRateLimiter _rateLimiter;
    private readonly IDroppedFloodAggregator _droppedFloodAggregator;
    private readonly PipelineCounters _counters;
    private readonly SensorOptions _options;
    private readonly object _gate = new();
    private CancellationTokenSource? _cts;
    private Task? _captureTask;
    private int _running;

    /// <summary>Задержка после ошибки чтения драйвера (не-горячая ветка, R4).</summary>
    private const int ErrorBackoffMs = 100;

    /// <summary>Интервал троттлинг-лога отдельного пакета (мс): ~5 раз/сек.</summary>
    private const long PacketLogIntervalMs = 200;

    /// <summary>Интервал сводной статистики (мс): раз в 5 секунд.</summary>
    private const long StatsIntervalMs = 5000;

    /// <summary>Интервал троттлинг-предупреждения о DDoS-флуде (мс): не чаще 1 раза в 5 с.</summary>
    private const long RateLimitWarningIntervalMs = 5000;

    private long _totalPackets;
    private long _parsedIpv4;
    private long _lastPacketLogTick;
    private long _lastStatsTick;
    private long _lastRateLimitWarningTick;
    private long _lastRateLimitCount;

    public PcapCaptureService(
        ILogger<PcapCaptureService> logger,
        INetworkDeviceProvider deviceProvider,
        IPacketRateLimiter rateLimiter,
        IDroppedFloodAggregator droppedFloodAggregator,
        PipelineCounters counters,
        IOptions<SensorOptions> options)
    {
        _logger = logger;
        _deviceProvider = deviceProvider;
        _rateLimiter = rateLimiter;
        _droppedFloodAggregator = droppedFloodAggregator;
        _counters = counters;
        _options = options.Value;
    }

    public Task StartAsync(ChannelWriter<ParsedPacket> sink, CancellationToken ct)
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

    private void CaptureLoop(ChannelWriter<ParsedPacket> sink, CancellationToken ct)
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
                    _totalPackets++;

                    // Timestamp в тиках .NET (1 тик = 100 нс) из PosixTimeval (unix epoch).
                    long ticks = (long)capture.Header.Timeval.Seconds * TimeSpan.TicksPerSecond
                                 + (long)capture.Header.Timeval.MicroSeconds * 10;

                    if (!PacketParser.TryParse(data, ticks, out ParsedPacket packet))
                    {
                        continue; // не-IPv4/битые — молча пропускаем, без аллокаций.
                    }

                    _parsedIpv4++;

                    // Копия (16 байт, на стеке) нужна, т.к. `in` нельзя взять от свойства record struct.
                    IpAddr srcIp = packet.SrcIp;
                    if (!_rateLimiter.IsAllowed(in srcIp))
                    {
                        _counters.IncrementRateLimited();
                        _droppedFloodAggregator.RecordDropped(in packet);
                        LogRateLimitWarningIfDue();
                        continue;
                    }

                    // Пишем разобранный пакет напрямую (zero-alloc), без промежуточного маппинга.
                    sink.TryWrite(packet);

                    if (_options.LogPacketDetail)
                    {
                        LogPacketIfDue(packet);
                    }

                    LogStatsIfDue();
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

            // Сигнализируем Consumer о завершении потока пакетов. TryComplete идемпотентен.
            sink.TryComplete();
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

    /// <summary>
    /// Троттлинг-лог отдельного пакета: не чаще ~5 раз/сек.
    /// Строковые аллокации (ToString/interpolation) происходят только здесь, вне hot path.
    /// </summary>
    private void LogPacketIfDue(in ParsedPacket packet)
    {
        long now = Environment.TickCount64;
        if (now - _lastPacketLogTick < PacketLogIntervalMs)
        {
            return;
        }

        _lastPacketLogTick = now;
        _logger.LogInformation(
            "{SrcMac} -> {SrcIp} -> {SrcPort} -> {Protocol} -> {Flags} -> {Bytes}",
            packet.SrcMac.ToString(),
            FormatIpv4(packet.SrcIp),
            packet.SrcPort,
            ProtocolName(packet.Protocol),
            FormatTcpFlags(packet.TcpFlags),
            packet.TotalBytes);
    }

    /// <summary>
    /// Сводная статистика раз в <see cref="StatsIntervalMs"/>. Аллокации только здесь (не-горячая ветка).
    /// </summary>
    private void LogStatsIfDue()
    {
        long now = Environment.TickCount64;
        if (now - _lastStatsTick < StatsIntervalMs)
        {
            return;
        }

        _lastStatsTick = now;
        _logger.LogInformation(
            "Всего пакетов: {Total} | Разобрано IPv4: {Ipv4} | Отброшено RateLimiter: {Dropped} | Память GC (МБ): {Mem}",
            _totalPackets,
            _parsedIpv4,
            _counters.RateLimited,
            GC.GetTotalMemory(false) / 1024 / 1024);
    }

    /// <summary>Предупреждение о DDoS-флуде не чаще 1 раза в 5 с (защита логгера от флуда).</summary>
    private void LogRateLimitWarningIfDue()
    {
        long now = Environment.TickCount64;
        if (now - _lastRateLimitWarningTick < RateLimitWarningIntervalMs)
        {
            return;
        }

        long total = _counters.RateLimited;
        long sinceLast = total - _lastRateLimitCount;
        _lastRateLimitWarningTick = now;
        _lastRateLimitCount = total;

        if (sinceLast > 0)
        {
            _logger.LogWarning(
                "Обнаружен DDoS-флуд: за {Interval} с отброшено {Dropped} пакетов (rate limiter).",
                RateLimitWarningIntervalMs / 1000,
                sinceLast);
        }
    }

    /// <summary>Форматирует IPv4 (младшие 32 бита Low) в dotted-quad. Только для веток логирования.</summary>
    private static string FormatIpv4(IpAddr ip)
    {
        uint v = (uint)ip.Low;
        return $"{(byte)(v >> 24)}.{(byte)(v >> 16)}.{(byte)(v >> 8)}.{(byte)v}";
    }

    /// <summary>Имя протокола для лога. Только для веток логирования.</summary>
    private static string ProtocolName(byte protocol) => protocol switch
    {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        _ => protocol.ToString(),
    };

    /// <summary>Форматирует TCP-флаги в "[Ack Psh]" (или "[]" при отсутствии). Только для веток логирования.</summary>
    private static string FormatTcpFlags(TcpFlags flags)
    {
        var sb = new System.Text.StringBuilder("[", 24);
        Append(flags, TcpFlags.Fin, "Fin", sb);
        Append(flags, TcpFlags.Syn, "Syn", sb);
        Append(flags, TcpFlags.Rst, "Rst", sb);
        Append(flags, TcpFlags.Psh, "Psh", sb);
        Append(flags, TcpFlags.Ack, "Ack", sb);
        Append(flags, TcpFlags.Urg, "Urg", sb);
        Append(flags, TcpFlags.Ece, "Ece", sb);
        Append(flags, TcpFlags.Cwr, "Cwr", sb);
        return sb.Append(']').ToString();
    }

    private static void Append(TcpFlags flags, TcpFlags bit, string name, System.Text.StringBuilder sb)
    {
        if ((flags & bit) != 0)
        {
            if (sb.Length > 1)
            {
                sb.Append(' ');
            }

            sb.Append(name);
        }
    }
}
