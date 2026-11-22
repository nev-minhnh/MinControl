using System.Diagnostics;
using Microsoft.Win32;

namespace MinControl.Service.Hosting;

/// <summary>
/// Installation-time registration of the MinControl service. NOT called by the service itself; intended to be
/// invoked from MinControl.Setup (elevated). Never run it on a development machine.
/// <list type="bullet">
/// <item>Service: LocalSystem, auto-start, unrestricted service SID.</item>
/// <item>Recovery (spec 8.1): restart after 0 s on 1st/2nd/subsequent failure, failure counter reset after 1 day,
///   recovery actions also on non-crash failures (<c>failureflag 1</c>).</item>
/// <item>Safe Mode (spec 8.1/8.8): <c>HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\{Minimal,Network}\MinControl</c>
///   with default value "Service", so the service also starts in Safe Mode (with/without networking).</item>
/// <item>Service DACL: the default SCM DACL already denies stop/config to non-admins; we keep it.</item>
/// </list>
/// </summary>
public static class ServiceInstaller
{
    public const string ServiceName = "MinControl";
    public const string DisplayName = "MinControl";
    private const string SafeBootKey = @"SYSTEM\CurrentControlSet\Control\SafeBoot";

    /// <summary>The sc.exe argument lists Install runs, in order (exposed for review / Setup logging).</summary>
    public static IReadOnlyList<string[]> InstallCommands(string serviceExePath) =>
    [
        ["create", ServiceName, "binPath=", $"\"{serviceExePath}\"", "start=", "auto", "obj=", "LocalSystem", "DisplayName=", DisplayName],
        ["description", ServiceName, "MinControl parental control agent"],
        ["failure", ServiceName, "reset=", "86400", "actions=", "restart/0/restart/0/restart/0"],
        ["failureflag", ServiceName, "1"],
        ["sidtype", ServiceName, "unrestricted"],
    ];

    public static void Install(string serviceExePath)
    {
        if (!File.Exists(serviceExePath)) throw new FileNotFoundException("service executable missing", serviceExePath);
        foreach (var args in InstallCommands(serviceExePath)) RunSc(args, allowFailure: false);
        foreach (var mode in new[] { "Minimal", "Network" })
        {
            using var key = Registry.LocalMachine.CreateSubKey($@"{SafeBootKey}\{mode}\{ServiceName}", writable: true);
            key.SetValue(null, "Service", RegistryValueKind.String);
        }
        RunSc(["start", ServiceName], allowFailure: true);
    }

    public static void Uninstall()
    {
        RunSc(["stop", ServiceName], allowFailure: true);
        RunSc(["delete", ServiceName], allowFailure: true);
        foreach (var mode in new[] { "Minimal", "Network" })
            Registry.LocalMachine.DeleteSubKeyTree($@"{SafeBootKey}\{mode}\{ServiceName}", throwOnMissingSubKey: false);
    }

    private static void RunSc(string[] args, bool allowFailure)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("cannot start sc.exe");
        var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0 && !allowFailure)
            throw new InvalidOperationException($"sc.exe {string.Join(' ', args)} failed ({p.ExitCode}): {output.Trim()}");
    }
}
