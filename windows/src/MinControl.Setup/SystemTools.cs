using System.Diagnostics;
using Microsoft.Win32;

namespace MinControl.Setup;

/// <summary>Thin wrappers over sc.exe / msiexec / the registry used by install, status and uninstall.</summary>
internal static class SystemTools
{
    public const string ServiceName = "MinControl";
    public const string ProductName = "MinControl";
    private const string SafeBootKey = @"SYSTEM\CurrentControlSet\Control\SafeBoot";
    private const string ProfileListKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    public static readonly string[] SafeBootModes = ["Minimal", "Network"];

    // ------------------------------------------------------------------ processes

    public static (int ExitCode, string Output) Run(string exe, params string[] args)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException($"cannot start {exe}");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        return (p.ExitCode, (stdout.Result + stderr.Result).Trim());
    }

    private static string Sc => Path.Combine(Environment.SystemDirectory, "sc.exe");

    // ------------------------------------------------------------------ service

    /// <summary>"RUNNING", "STOPPED", … or null when the service does not exist.</summary>
    public static string? ServiceState()
    {
        var (rc, output) = Run(Sc, "query", ServiceName);
        if (rc != 0) return null;
        foreach (var line in output.Split('\n'))
        {
            var t = line.Trim();
            if (!t.StartsWith("STATE", StringComparison.OrdinalIgnoreCase)) continue;
            var parts = t.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return parts.Length >= 4 ? parts[3] : t;
        }
        return "UNKNOWN";
    }

    public static string ServiceConfigText() => Run(Sc, "qc", ServiceName).Output;

    public static string ServiceFailureText() => Run(Sc, "qfailure", ServiceName).Output;

    /// <summary>Stops the service and waits until it is STOPPED (or the timeout passes). True when stopped/absent.</summary>
    public static bool StopService(TimeSpan timeout)
    {
        var state = ServiceState();
        if (state is null or "STOPPED") return true;
        // Tell the service this stop is planned (no tamper.service_stopped alert). Best effort.
        MinControl.Core.Storage.ExpectedStopMarker.Write(new MinControl.Core.Storage.DataPaths().ExpectedStop, "setup", DateTimeOffset.UtcNow);
        Run(Sc, "stop", ServiceName);
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            state = ServiceState();
            if (state is null or "STOPPED") return true;
            Thread.Sleep(500);
        }
        return false;
    }

    /// <summary>sc start (does not wait for RUNNING). Exit code 1056 = already running.</summary>
    public static (int ExitCode, string Output) StartService()
    {
        var r = Run(Sc, "start", ServiceName);
        return r.ExitCode == 1056 ? (0, r.Output) : r;
    }

    public static bool DeleteService() => Run(Sc, "delete", ServiceName).ExitCode == 0;

    /// <summary>Kills leftover helper / native-host processes so MSI can remove the files. Best effort.</summary>
    public static int KillAgentProcesses()
    {
        int killed = 0;
        foreach (var name in new[] { "MinControl.Session", "MinControl.NativeHost" })
        {
            foreach (var p in Process.GetProcessesByName(name))
            {
                using (p)
                {
                    try { p.Kill(); p.WaitForExit(5000); killed++; }
                    catch (Exception e) { Console.Error.WriteLine($"  could not stop {name} ({p.Id}): {e.Message}"); }
                }
            }
        }
        return killed;
    }

    // ------------------------------------------------------------------ registry

    public static bool SafeBootRegistered(string mode)
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"{SafeBootKey}\{mode}\{ServiceName}");
        return key?.GetValue(null) is "Service";
    }

    public static void RemoveSafeBootKeys()
    {
        foreach (var mode in SafeBootModes)
            Registry.LocalMachine.DeleteSubKeyTree($@"{SafeBootKey}\{mode}\{ServiceName}", throwOnMissingSubKey: false);
    }

    /// <summary>All real user profiles on the machine (local and Microsoft-account users): SID → profile path.</summary>
    public static IReadOnlyDictionary<string, string> UserProfiles()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var list = Registry.LocalMachine.OpenSubKey(ProfileListKey);
        if (list is null) return result;
        foreach (var sid in list.GetSubKeyNames())
        {
            if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) || sid.EndsWith(".bak", StringComparison.OrdinalIgnoreCase)) continue;
            using var k = list.OpenSubKey(sid);
            if (k?.GetValue("ProfileImagePath") is string p) result[sid] = Environment.ExpandEnvironmentVariables(p);
        }
        return result;
    }

    /// <summary>Product code of the installed MinControl MSI (64-bit uninstall view), or null.</summary>
    public static string? InstalledProductCode()
    {
        using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(UninstallKey);
        if (root is null) return null;
        foreach (var name in root.GetSubKeyNames())
        {
            if (!name.StartsWith('{')) continue;
            using var k = root.OpenSubKey(name);
            if (k?.GetValue("DisplayName") is ProductName && k.GetValue("WindowsInstaller") is 1) return name;
        }
        return null;
    }

    public static string? InstalledVersion(string productCode)
    {
        using var k = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey($@"{UninstallKey}\{productCode}");
        return k?.GetValue("DisplayVersion") as string;
    }
}
