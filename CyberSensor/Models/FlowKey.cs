namespace CyberSensor.Models;

/// <summary>
/// Ключ сессии (flow): 5-tuple без учёта направления.
/// </summary>
public readonly record struct FlowKey(
    IpAddr SourceAddress,
    IpAddr DestinationAddress,
    ushort SourcePort,
    ushort DestinationPort,
    byte Protocol);
