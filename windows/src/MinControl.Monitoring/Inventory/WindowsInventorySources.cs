using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using MinControl.Core.Abstractions;

namespace MinControl.Monitoring.Inventory;

/// <summary>Production sources: registry (HKLM / WOW6432Node / HKU\sid loaded hives), Start-menu .lnk files, AppX registry.</summary>
internal sealed class WindowsInventorySources : IInventorySources
{
    private const string UninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string AppxRepoPath =
        @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
    private static readonly string[] FrameworkPrefixes =
    [
        "Microsoft.VCLibs", "Microsoft.NET.", "Microsoft.UI.Xaml", "Microsoft.WindowsAppRuntime",
        "Microsoft.Services.Store.Engagement", "Microsoft.Advertising", "Microsoft.DirectX", "Windows.", "Microsoft.Windows.",
        "MicrosoftWindows.", "Microsoft.Win32WebViewHost", "NcsiUwpApp", "Microsoft.AAD", "Microsoft.AccountsControl",
        "Microsoft.LockApp", "Microsoft.CredDialogHost", "Microsoft.ECApp", "Microsoft.AsyncTextService", "Microsoft.BioEnrollment",
    ];

    private readonly IUserDirectory _users;
    private readonly ILogger _log;

    public WindowsInventorySources(IUserDirectory users, ILogger log) { _users = users; _log = log; }

    public IReadOnlyList<RawUninstall> Uninstalls(string sid)
    {
        var list = new List<RawUninstall>();
        void Scan(RegistryKey? root)
        {
            if (root is null) return;
            using (root)
                foreach (var name in root.GetSubKeyNames())
                    try { using var sub = root.OpenSubKey(name); if (sub is not null && UninstallParser.Parse(sub.GetValue) is { } u) list.Add(u); }
                    catch { }
        }
        Scan(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(UninstallPath));
        Scan(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32).OpenSubKey(UninstallPath));
        try { Scan(Registry.Users.OpenSubKey(sid + "\\" + UninstallPath)); } catch { }
        return list;
    }

    public IReadOnlyList<RawShortcut> Shortcuts(string sid)
    {
        var dirs = new List<string>
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs"),
        };
        if (_users.ProfilePath(sid) is { Length: > 0 } profile)
            dirs.Add(Path.Combine(profile, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs"));
        var list = new List<RawShortcut>();
        foreach (var dir in dirs)
        {
            if (!Directory.Exists(dir)) continue;
            List<string> files;
            try { files = Directory.EnumerateFiles(dir, "*.lnk", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true }).ToList(); }
            catch { continue; }
            foreach (var f in files)
            {
                var target = ShellLink.Resolve(f);
                if (target is not null) list.Add(new RawShortcut(Path.GetFileNameWithoutExtension(f), target));
            }
        }
        return list;
    }

    public IReadOnlyList<RawAppx> Appx(string sid)
    {
        var list = new List<RawAppx>();
        try
        {
            using var root = Registry.Users.OpenSubKey(sid + "\\" + AppxRepoPath);
            if (root is null) return list;
            foreach (var full in root.GetSubKeyNames())
            {
                var parts = full.Split('_');   // Name_Version_Arch_ResourceId_PublisherId
                if (parts.Length != 5 || parts[3].Length != 0) continue;
                if (FrameworkPrefixes.Any(p => parts[0].StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;
                try
                {
                    using var sub = root.OpenSubKey(full);
                    if (sub is null) continue;
                    if (sub.GetValue("IsFramework") is int fw && fw == 1) continue;
                    list.Add(new RawAppx(parts[0], sub.GetValue("DisplayName") as string, parts[1],
                        sub.GetValue("PackageRootFolder") as string, null));
                }
                catch { }
            }
        }
        catch (Exception ex) { _log.LogDebug(ex, "AppX scan failed for {Sid}", sid); }
        return list;
    }
}

/// <summary>Minimal IShellLinkW wrapper: .lnk → target path.</summary>
internal static class ShellLink
{
    [ComImport, Guid("00021401-0000-0000-C000-000000000046")] private class CShellLink { }

    [ComImport, Guid("000214F9-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellLinkW
    {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszFile, int cch, nint pfd, uint fFlags);
    }

    [ComImport, Guid("0000010b-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IPersistFile
    {
        void GetClassID(out Guid g);
        [PreserveSig] int IsDirty();
        void Load([MarshalAs(UnmanagedType.LPWStr)] string file, uint mode);
    }

    /// <summary>Runs on a dedicated STA thread; returns null on any failure.</summary>
    public static string? Resolve(string lnk)
    {
        string? result = null;
        var t = new Thread(() =>
        {
            try
            {
                var link = new CShellLink();
                ((IPersistFile)link).Load(lnk, 0);
                var sb = new System.Text.StringBuilder(520);
                ((IShellLinkW)link).GetPath(sb, sb.Capacity, 0, 0);
                var p = Environment.ExpandEnvironmentVariables(sb.ToString());
                result = string.IsNullOrWhiteSpace(p) ? null : p;
                Marshal.FinalReleaseComObject(link);
            }
            catch { }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.IsBackground = true;
        t.Start();
        return t.Join(5000) ? result : null;
    }
}
