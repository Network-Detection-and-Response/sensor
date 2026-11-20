# CyberSensor — локальный сенсор NDR

Пассивный сетевой сенсор (локальный агент) учебной системы **Network Detection and Response (NDR)**. Перехватывает трафик на сетевом интерфейсе, агрегирует пакеты в NetFlow-подобные сессии и отправляет их батчами на бэкенд по HTTP.

Это один из четырёх модулей распределённой системы:

| Модуль | Роль |
|---|---|
| **Сенсор** (этот репозиторий) | перехват трафика, агрегация сессий, отправка батчей |
| Бэкенд (Go) | приём батчей, PostgreSQL, детектирование инцидентов |
| ML-модуль | скоринг сессий (опционально) |
| Дашборд | веб-панель оператора |

> Сенсор не отправляет «сырой» трафик (payload) — только агрегированные метаданные сессий.

## Пайплайн обработки

```
L2/L3 интерфейс (SharpPcap / Npcap, promiscuous-режим)
      │
      ▼
Парсинг заголовков Ethernet / IPv4 / TCP / UDP / ICMP  (zero-alloc, Span<T> + BinaryPrimitives)
      │
      ▼
Rate Limiter — Fixed Window Counter per-IP (детерминированный DDoS-фильтр, защита от spoofing)
      │
      ▼
BoundedChannel<ParsedPacket>  (DropOldest, Producer-Consumer)
      │
      ▼
Агрегация сессий по ключу 5-tuple (FlowTable, экспирация по idle/hard/RST)
      │  периодический flush (3 с)
      ▼
Батч CompletedFlow → POST /api/v1/flows  (JSON snake_case)
```

Горячий путь (захват → парсинг → rate-limit → канал → агрегация) реализован без аллокаций: `Span<T>`/`ReadOnlySpan<T>`, `struct`/`readonly record struct`, `CollectionsMarshal.GetValueRefOrAddDefault`, `static`-лямбды, `Interlocked`. Отправка на бэкенд полностью асинхронна и не блокирует поток захвата.

## Стек

- **C# 12 / .NET 8**
- **SharpPcap + PacketDotNet** — перехват и разбор трафика
- **System.Threading.Channels** — неблокирующий конвейер Producer-Consumer
- **System.Text.Json source-generator** — низкоаллокационная сериализация без рефлексии
- **xUnit + FakeTimeProvider** — unit-тесты (детерминированные, без `Thread.Sleep`)

## Требования

- **Windows x64**
- **[Npcap](https://npcap.com)** — драйвер захвата трафика (устанавливается отдельно). Без него сенсор аварийно останавливается при старте с понятным сообщением `NpcapUnavailableException`.
- **Права администратора** — для promiscuous-режима и захвата на интерфейсе.
- **.NET 8 SDK** — только для сборки из исходников. Release-сборка self-contained, SDK на целевой машине не нужен.

## Структура проекта

```
CyberSensor/
├── Program.cs                    — точка входа, DI, Windows Service, EventLog
├── appsettings.json              — конфигурация (production)
├── appsettings.Development.json  — override для локальной отладки
├── Configuration/                — SensorOptions + кросс-полевая валидация
├── Abstractions/                 — интерфейсы (ICaptureService, IPacketRateLimiter, IFlowAggregator, IBatchSender, IDroppedFloodAggregator)
├── Capture/                      — PcapCaptureService, PacketParser, выбор интерфейса
├── RateLimiting/                 — FastRateLimiter (Fixed Window Counter)
├── Aggregation/                  — FlowTable, FlowAggregator, DroppedFloodAggregator
├── Sending/                      — HttpBatchSender (HTTP + отказоустойчивость)
├── Workers/                      — CaptureWorker, AggregationWorker, BatchDispatcherWorker
├── Models/                       — value-types (ParsedPacket, FlowKey, FlowMetrics, CompletedFlow, IpAddr, MacAddress, TcpFlags)
├── Dto/                          — JSON-контракт (FlowDto, FlowBatchRequest, TcpFlagsDto)
└── Diagnostics/                  — PipelineCounters, PipelineState

CyberSensor.Tests/                — unit-тесты (xUnit, net8.0)
scripts/                          — публикация и установка службы
```

## Быстрый старт (development)

```powershell
# сборка
dotnet build CyberSensor/CyberSensor.csproj -c Release

# запуск в консольном режиме (для отладки)
dotnet run --project CyberSensor -c Release

# тесты
dotnet test CyberSensor.Tests/CyberSensor.Tests.csproj -c Release
```

При старте сенсор выводит в лог нумерованный список найденных сетевых интерфейсов (`Index`, `Name`, `Description`, MAC) и выбирает устройство по конфигурации. По умолчанию (`NetworkInterfaceName = ""`, `NetworkInterfaceIndex = 0`) берётся интерфейс с индексом `0`. Чтобы захватывать конкретную карту, задайте в `appsettings.Development.json` имя (регистронезависимое вхождение) или индекс:

```json
{ "Sensor": { "NetworkInterfaceName": "Intel" } }
```

Если заданное имя/индекс не найдено — сенсор **fail-fast**: логирует `LogCritical` со списком доступных интерфейсов и останавливается (тихий fallback на случайный интерфейс недопустим для ИБ-задачи).

## Конфигурация (`appsettings.json`)

| Секция / ключ | По умолчанию | Назначение |
|---|---|---|
| `Sensor.SensorId` | `core_switch_mirror` | Идентификатор сенсора (snake_case), уходит в `sensor_id` |
| `Sensor.NetworkInterfaceName` | `""` | Имя/фрагмент описания интерфейса для поиска (пусто → по индексу) |
| `Sensor.NetworkInterfaceIndex` | `0` | Индекс интерфейса из стартового списка |
| `Sensor.CaptureFilter` | `ip` | BPF-фильтр |
| `Sensor.Snaplen` | `65536` | Длина среза пакета |
| `Sensor.PromiscuousMode` | `true` | Неразборчивый режим (L2/L3 + MAC) |
| `Sensor.ReadTimeoutMilliseconds` | `1000` | Таймаут чтения (задержка реакции на остановку) |
| `Sensor.LogPacketDetail` | `false` | Построчный лог пакетов (только для отладки парсера) |
| `RateLimiter.MaxPacketsPerSecondPerIp` | `3000` | Лимит пакетов/с с одного IP |
| `RateLimiter.MaxTrackedIps` | `65536` | Максимум уникальных IP в окне (защита от spoofing/OOM) |
| `RateLimiter.RateLimiterEnabled` | `true` | `false` — отключить фильтр (снятие нефильтрованного дампа для ML) |
| `Aggregator.FlowTableCapacity` | `65536` | Предвыделение таблицы сессий |
| `Aggregator.FlowIdleTimeout` | `00:00:30` | Экспирация сессии по простою |
| `Aggregator.FlowHardTimeout` | `00:05:00` | Жёсткий потолок жизни сессии |
| `Channels.PacketChannelCapacity` | `50000` | Ёмкость входного канала пакетов (DropOldest) |
| `Batch.MaxBatchSize` | `500` | Макс. сессий в одном POST |
| `Batch.FlushInterval` | `00:00:03` | Шаг таймера выгрузки батчей |
| `Backend.BaseUrl` | `http://localhost:8080` | URL бэкенда |
| `Backend.FlowsEndpoint` | `/api/v1/flows` | Путь приёма батчей |
| `Backend.ApiKey` | `change-me-sensor-key` | API-ключ сенсора |
| `Backend.Timeout` | `00:00:10` | Таймаут HTTP |

Ключ можно переопределить переменной окружения без правки файла:

```powershell
$env:Sensor__Backend__ApiKey = "реальный-ключ"
```

## Release-публикация и Windows Service

### Публикация (self-contained single-file)

```powershell
# вручную
dotnet publish CyberSensor/CyberSensor.csproj -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:DebugType=None -p:DebugSymbols=false -o ./publish/win-x64

# или готовым скриптом
.\scripts\publish.ps1
```

В `publish/win-x64/` появится единый `CyberSensor.exe` (~66 МБ) и редактируемый `appsettings.json` рядом (конфиг не вшит внутрь exe).

### Установка/удаление как службы

```powershell
# установка (нужны права администратора)
.\scripts\install-service.ps1

# удаление
.\scripts\uninstall-service.ps1
```

Служба называется `CyberSensor`. Под SCM конфиг читается из каталога исполняемого файла (не из `C:\Windows\System32`), а события уровня `Information` (старт, выбранный интерфейс, остановка) пишутся в Журнал Windows (`Application`, источник `CyberSensor`).

## Контракт с бэкендом

Сенсор шлёт `POST /api/v1/flows` с заголовком **`X-Sensor-API-Key`** (значение из `Backend.ApiKey`, на стороне бэкенда — `SENSOR_API_KEY`):

```json
{
  "sensor_id": "core_switch_mirror",
  "timestamp": "2026-10-09T14:30:00Z",
  "flows": [
    {
      "src_ip": "192.168.1.50",
      "src_mac": "00:1A:2B:3C:4D:5E",
      "dst_ip": "10.0.0.5",
      "dst_mac": "AA:BB:CC:DD:EE:FF",
      "src_port": 54321,
      "dst_port": 443,
      "protocol": "TCP",
      "duration_ms": 1500,
      "total_packets": 45,
      "total_bytes": 35000,
      "tcp_flags": { "syn": 1, "ack": 40, "rst": 0 }
    }
  ]
}
```

Сводка заблокированного DDoS-флуда отправляется в том же массиве `flows` как обычная запись с `src_port = 0` (маркер агрегированного флуда со всех портов отправителя) — без добавления новых полей в JSON.

## Отказоустойчивость и остановка

- **Недоступность бэкенда не останавливает сенсор.** `HttpRequestException`/таймаут/неуспешные коды логируются предупреждением, счётчики `FailedBatches`/`FailedFlows` растут, буфер очищается — захват продолжается.
- **Graceful shutdown (Ctrl+C / остановка службы):** корректно закрывается устройство захвата, канал пакетов дренируется, агрегатор делает финальный `DrainAll`, а оставшийся батч уходит в сеть в пределах отдельного 5-секундного дедлайна. Данные не теряются.
- **Rate limiter** — детерминированный Fixed Window Counter (сброс окна раз в секунду, `TimeProvider` для тестируемости), защита от раздувания словаря при IP-spoofing через `MaxTrackedIps`.

## Тесты

```powershell
dotnet test CyberSensor.Tests/CyberSensor.Tests.csproj -c Release
```

Покрытие:
- `FastRateLimiter` — лимит пакетов, per-IP изоляция, сброс окна через 1 с, режим отключения (`FakeTimeProvider`, без `Thread.Sleep`).
- `DroppedFloodAggregator` — схлопывание флуда в одну запись (`src_port = 0`), независимость источников, очистка после drain, защита от spoofing.
