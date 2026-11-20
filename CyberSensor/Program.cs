using System.Runtime;
using System.Runtime.Versioning;
using System.Threading.Channels;
using CyberSensor.Abstractions;
using CyberSensor.Aggregation;
using CyberSensor.Capture;
using CyberSensor.Configuration;
using CyberSensor.Diagnostics;
using CyberSensor.Models;
using CyberSensor.RateLimiting;
using CyberSensor.Sending;
using CyberSensor.Workers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.EventLog;
using Microsoft.Extensions.Options;

GCSettings.LatencyMode = GCLatencyMode.SustainedLowLatency;

var hostSettings = new HostApplicationBuilderSettings
{
    Args = args,
    // ContentRootPath всегда на каталоге исполняемого файла:
    //  - под Windows SCM рабочий каталог = C:\Windows\System32 (иначе конфиг не найдётся);
    //  - при `dotnet run` из родительского каталога рабочий каталог ≠ каталогу сборки.
    // Единый AppContext.BaseDirectory надёжнее условного IsWindowsService().
    ContentRootPath = AppContext.BaseDirectory,
};
var builder = Host.CreateApplicationBuilder(hostSettings);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "CyberSensor";
});

// EventLog подключаем только при запуске как служба Windows:
// консольный запуск не должен писать в Журнал Windows.
if (OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService())
{
    ConfigureWindowsEventLog(builder.Logging);
}

builder.Services.AddOptions<SensorOptions>()
    .Bind(builder.Configuration.GetSection(SensorOptions.SectionName))
    .ValidateDataAnnotations()
    .ValidateOnStart();

// Общие счётчики конвейера (диагностика: вытеснение канала и пр.).
builder.Services.AddSingleton<PipelineCounters>();

// Состояние конвейера: сигнал завершения агрегации для корректного финального drain.
builder.Services.AddSingleton<PipelineState>();

// Producer-Consumer каналы (bounded) с опциями из конфигурации.
builder.Services.AddSingleton(sp =>
{
    var channels = sp.GetRequiredService<IOptions<SensorOptions>>().Value.Channels;
    var counters = sp.GetRequiredService<PipelineCounters>();
    var options = new BoundedChannelOptions(channels.PacketChannelCapacity)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleWriter = true,   // пишет только поток захвата
        SingleReader = true,   // читает только AggregationWorker
        AllowSynchronousContinuations = false, // consumer не выполняется на потоке захвата Npcap
    };
    return Channel.CreateBounded<ParsedPacket>(options, counters.OnChannelDrop);
});

builder.Services.AddSingleton<INetworkDeviceProvider, NetworkDeviceProvider>();
builder.Services.AddSingleton<ICaptureService, PcapCaptureService>();
builder.Services.AddSingleton<TimeProvider>(TimeProvider.System);
builder.Services.AddSingleton<IPacketRateLimiter, FastRateLimiter>();
builder.Services.AddSingleton<IFlowAggregator, FlowAggregator>();
builder.Services.AddSingleton<IDroppedFloodAggregator, DroppedFloodAggregator>();

builder.Services.AddSingleton<IValidateOptions<SensorOptions>, SensorOptionsValidator>();

builder.Services.AddHttpClient<IBatchSender, HttpBatchSender>((sp, client) =>
{
    var backend = sp.GetRequiredService<IOptions<SensorOptions>>().Value.Backend;

    // Абсолютный URL гарантирован валидацией [Required] + [Url] на старте (ValidateOnStart).
    client.BaseAddress = new Uri(backend.BaseUrl, UriKind.Absolute);
    client.Timeout = backend.Timeout;

    // Имя заголовка API-ключа зафиксировано: "X-Sensor-API-Key".
    client.DefaultRequestHeaders.Add("X-Sensor-API-Key", backend.ApiKey);
});

builder.Services.AddHostedService<CaptureWorker>();
builder.Services.AddHostedService<AggregationWorker>();
builder.Services.AddHostedService<BatchDispatcherWorker>();

var host = builder.Build();

await host.RunAsync();

// Выделено в локальную функцию с [SupportedOSPlatform("windows")]:
// анализатор CA1416 не умеет переносить platform guard в тело лямбды,
// поэтому настройку EventLog задаём объектом, а не лямбдой.
[SupportedOSPlatform("windows")]
static void ConfigureWindowsEventLog(ILoggingBuilder logging)
{
    logging.AddEventLog(new EventLogSettings { SourceName = "CyberSensor" });
}
