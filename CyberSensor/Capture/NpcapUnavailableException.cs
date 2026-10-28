namespace CyberSensor.Capture;

/// <summary>
/// Доменное исключение: драйвер Npcap/WinPcap недоступен или не может быть использован
/// (не установлен, нет прав администратора, сбой загрузки нативной библиотеки).
/// </summary>
public sealed class NpcapUnavailableException : Exception
{
    public NpcapUnavailableException(string message)
        : base(message)
    {
    }

    public NpcapUnavailableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
