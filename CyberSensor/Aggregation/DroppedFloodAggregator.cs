using System.Runtime.InteropServices;
using CyberSensor.Abstractions;
using CyberSensor.Configuration;
using CyberSensor.Models;
using Microsoft.Extensions.Options;

namespace CyberSensor.Aggregation;

/// <summary>Агрегатор отброшенных пакетов (DDoS-флуд) по SrcIp. Zero-alloc, потокобезопасный через lock.</summary>
public sealed class DroppedFloodAggregator : IDroppedFloodAggregator
{
    private readonly Dictionary<IpAddr, DroppedFloodSummary> _dropped;
    private readonly int _maxTrackedIps;
    private readonly object _lock = new();

    public DroppedFloodAggregator(IOptions<SensorOptions> options)
    {
        _maxTrackedIps = options.Value.RateLimiter.MaxTrackedIps;
        _dropped = new Dictionary<IpAddr, DroppedFloodSummary>();
    }

    public void RecordDropped(in ParsedPacket packet)
    {
        long timestampMs = packet.TimestampTicks / TimeSpan.TicksPerMillisecond;

        lock (_lock)
        {
            // Защита от IP-spoofing: не даём словарю раздуться бесконечно.
            if (_dropped.Count >= _maxTrackedIps && !_dropped.ContainsKey(packet.SrcIp))
            {
                return;
            }

            ref DroppedFloodSummary entry = ref CollectionsMarshal.GetValueRefOrAddDefault(_dropped, packet.SrcIp, out bool exists);
            if (!exists)
            {
                entry.SrcMac = packet.SrcMac;
                entry.DstIp = packet.DstIp;
                entry.DstMac = packet.DstMac;
                entry.DstPort = packet.DstPort;
                entry.Protocol = packet.Protocol;
                entry.FirstSeenMs = timestampMs;
                entry.LastSeenMs = timestampMs;
                entry.TotalPackets = 1;
                entry.TotalBytes = packet.TotalBytes;
                entry.SynCount = (packet.TcpFlags & TcpFlags.Syn) != 0 ? 1 : 0;
                entry.AckCount = (packet.TcpFlags & TcpFlags.Ack) != 0 ? 1 : 0;
                entry.RstCount = (packet.TcpFlags & TcpFlags.Rst) != 0 ? 1 : 0;
            }
            else
            {
                if (timestampMs > entry.LastSeenMs) entry.LastSeenMs = timestampMs;
                entry.TotalPackets++;
                entry.TotalBytes += packet.TotalBytes;
                if ((packet.TcpFlags & TcpFlags.Syn) != 0) entry.SynCount++;
                if ((packet.TcpFlags & TcpFlags.Ack) != 0) entry.AckCount++;
                if ((packet.TcpFlags & TcpFlags.Rst) != 0) entry.RstCount++;
                // последний целевой адрес/порт/протокол
                entry.DstIp = packet.DstIp;
                entry.DstMac = packet.DstMac;
                entry.DstPort = packet.DstPort;
                entry.Protocol = packet.Protocol;
            }
        }
    }

    public int DrainSummaries(List<CompletedFlow> destination)
    {
        int count = 0;
        lock (_lock)
        {
            foreach (KeyValuePair<IpAddr, DroppedFloodSummary> kv in _dropped)
            {
                IpAddr srcIp = kv.Key;
                DroppedFloodSummary s = kv.Value;

                var key = new FlowKey(srcIp, s.DstIp, 0, s.DstPort, s.Protocol); // SrcPort=0 — маркер флуда
                var metrics = new FlowMetrics
                {
                    SrcMac = s.SrcMac,
                    DstMac = s.DstMac,
                    FirstSeenMs = s.FirstSeenMs,
                    LastSeenMs = s.LastSeenMs,
                    TotalPackets = s.TotalPackets,
                    TotalBytes = s.TotalBytes,
                    SynCount = s.SynCount,
                    AckCount = s.AckCount,
                    RstCount = s.RstCount,
                };
                destination.Add(new CompletedFlow(key, metrics));
                count++;
            }
            _dropped.Clear();
        }
        return count;
    }
}
