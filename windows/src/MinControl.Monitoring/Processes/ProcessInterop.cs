using System.Text;
using MinControl.Monitoring.Native;

namespace MinControl.Monitoring.Processes;

/// <summary>Image-path resolution and termination. Abstracted so the orchestration can be faked.</summary>
public interface IProcessControl
{
    /// <summary>Win32 image path of a live process, or null.</summary>
    string? ImagePath(int pid);
    /// <summary>TerminateProcess after verifying the image path still matches (PID reuse guard).</summary>
    bool Terminate(int pid, string expectedPath);
}

internal sealed class ProcessControl : IProcessControl
{
    public string? ImagePath(int pid)
    {
        using var h = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        return h.IsInvalid ? null : QueryImage(h);
    }

    public bool Terminate(int pid, string expectedPath)
    {
        using var h = NativeMethods.OpenProcess(
            NativeMethods.PROCESS_TERMINATE | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h.IsInvalid) return false;
        var actual = QueryImage(h);
        if (actual is null || !string.Equals(actual, expectedPath, StringComparison.OrdinalIgnoreCase)) return false;
        return NativeMethods.TerminateProcess(h, 1);
    }

    private static string? QueryImage(Microsoft.Win32.SafeHandles.SafeProcessHandle h)
    {
        var sb = new StringBuilder(1024);
        int size = sb.Capacity;
        return NativeMethods.QueryFullProcessImageNameW(h, 0, sb, ref size) ? sb.ToString(0, size) : null;
    }
}

/// <summary>Converts NT device paths (\Device\HarddiskVolume3\...) from ETW to drive-letter paths.</summary>
internal static class DevicePathMap
{
    private static volatile Dictionary<string, string>? _map;
    private static long _builtAt;

    public static string ToDosPath(string ntPath)
    {
        if (ntPath.Length > 2 && ntPath[1] == ':') return ntPath;
        if (ntPath.StartsWith(@"\??\", StringComparison.Ordinal)) return ntPath[4..];
        if (ntPath.StartsWith(@"\Device\Mup\", StringComparison.OrdinalIgnoreCase)) return @"\\" + ntPath[12..];

        for (int attempt = 0; attempt < 2; attempt++)
        {
            var map = GetMap(force: attempt == 1);
            foreach (var (device, drive) in map)
            {
                if (ntPath.Length > device.Length && ntPath[device.Length] == '\\'
                    && ntPath.StartsWith(device, StringComparison.OrdinalIgnoreCase))
                    return drive + ntPath[device.Length..];
            }
        }
        return ntPath;
    }

    private static Dictionary<string, string> GetMap(bool force)
    {
        var m = _map;
        if (m is not null && !force && Environment.TickCount64 - Interlocked.Read(ref _builtAt) < 60_000) return m;

        var fresh = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var sb = new StringBuilder(1024);
        foreach (var drive in DriveInfo.GetDrives())
        {
            var letter = drive.Name[..2]; // "C:"
            sb.Clear();
            if (NativeMethods.QueryDosDeviceW(letter, sb, 1024) != 0)
                fresh[sb.ToString()] = letter;
        }
        _map = fresh;
        Interlocked.Exchange(ref _builtAt, Environment.TickCount64);
        return fresh;
    }
}
