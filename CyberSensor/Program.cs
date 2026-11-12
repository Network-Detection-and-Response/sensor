using System.Runtime;
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
using Microsoft.Extensions.Options;

GCSettings.LatencyMode = GCLatencyMode.SustainedLowLatency;

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    // Фиксируем content root на каталог сборки: там лежит appsettings*.json.
    // Без этого `dotnet run --project` из родительского каталога искал бы конфигурацию
    // в текущей рабочей директории и не находил бы её.
    ContentRootPath = AppContext.BaseDirectory,
    Args = args,
});

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "CyberSensor";
});

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
builder.Services.AddSingleton<IPacketRateLimiter, FastRateLimiter>();
builder.Services.AddSingleton<IFlowAggregator, FlowAggregator>();

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
