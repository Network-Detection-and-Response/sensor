using System.Runtime;
using System.Threading.Channels;
using CyberSensor.Abstractions;
using CyberSensor.Aggregation;
using CyberSensor.Capture;
using CyberSensor.Configuration;
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

// Producer-Consumer каналы (bounded) с опциями из конфигурации.
builder.Services.AddSingleton(sp =>
{
    var channels = sp.GetRequiredService<IOptions<SensorOptions>>().Value.Channels;
    return Channel.CreateBounded<PacketMeta>(new BoundedChannelOptions(channels.PacketChannelCapacity)
    {
        FullMode = ToBoundedFullMode(channels.PacketChannelFullMode),
        SingleReader = true,
        SingleWriter = false,
        AllowSynchronousContinuations = false,
    });
});

builder.Services.AddSingleton(sp =>
{
    var channels = sp.GetRequiredService<IOptions<SensorOptions>>().Value.Channels;
    return Channel.CreateBounded<FlowRecord>(new BoundedChannelOptions(channels.FlowChannelCapacity)
    {
        FullMode = ToBoundedFullMode(channels.FlowChannelFullMode),
        SingleReader = true,
        SingleWriter = false,
        AllowSynchronousContinuations = false,
    });
});

builder.Services.AddSingleton<INetworkDeviceProvider, NetworkDeviceProvider>();
builder.Services.AddSingleton<ICaptureService, PcapCaptureService>();
builder.Services.AddSingleton<IPacketRateLimiter, TokenBucketPacketRateLimiter>();
builder.Services.AddSingleton<IFlowAggregator, FlowAggregator>();

builder.Services.AddSingleton<IValidateOptions<SensorOptions>, SensorOptionsValidator>();

builder.Services.AddHttpClient<IBatchSender, HttpBatchSender>((sp, client) =>
{
    var backend = sp.GetRequiredService<IOptions<SensorOptions>>().Value.Backend;

    // Абсолютный URL гарантирован валидацией [Required] + [Url] на старте (ValidateOnStart).
    client.BaseAddress = new Uri(backend.BaseUrl, UriKind.Absolute);
    client.Timeout = backend.Timeout;

    // Имя заголовка API-ключа зафиксировано: "X-Api-Key".
    if (!string.IsNullOrWhiteSpace(backend.ApiKey))
    {
        client.DefaultRequestHeaders.Add("X-Api-Key", backend.ApiKey);
    }

    // MaxRetries в HttpClient нативно не настраивается (IHttpClientFactory не даёт retry-политику).
    // TODO(Шаг 1.3): реализовать ретраи в HttpBatchSender на основе Backend.MaxRetries.
});

builder.Services.AddHostedService<CaptureWorker>();
builder.Services.AddHostedService<AggregationWorker>();
builder.Services.AddHostedService<BatchDispatcherWorker>();

var host = builder.Build();

await host.RunAsync();

static BoundedChannelFullMode ToBoundedFullMode(ChannelFullMode mode) => mode switch
{
    ChannelFullMode.DropOldest => BoundedChannelFullMode.DropOldest,
    ChannelFullMode.DropNewest => BoundedChannelFullMode.DropNewest,
    ChannelFullMode.DropWrite => BoundedChannelFullMode.DropWrite,
    _ => BoundedChannelFullMode.Wait,
};
