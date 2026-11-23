using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using Microsoft.Win32;

namespace MinControl.Setup;

/// <summary>
/// "MinControl Connect" shortcuts for the administrator who installs MinControl, never for the children:
/// <list type="bullet">
/// <item>a desktop shortcut on THAT user's desktop (the per-machine MSI's DesktopFolder would be the public desktop that
///   every child sees);</item>
/// <item>a taskbar pin, Windows 11 only, through the supported route: the per-user "Start Layout" policy
///   (<c>HKCU\Software\Policies\Microsoft\Windows\Explorer</c> <c>StartLayoutFile</c> + <c>LockedStartLayout</c>, the
///   registry form of User Configuration &gt; Start Menu and Taskbar &gt; Start Layout) pointing at
///   <c>TaskbarLayout.xml</c> in the install folder (a <c>CustomTaskbarLayoutCollection</c> that appends the pin).
///   Programmatic pinning has no public API on Windows 10/11. The pin shows after the admin's next sign-in. An admin who
///   already has a Start Layout policy of their own keeps it (no pin then).</item>
/// </list>
/// The MSI runs this as SYSTEM with <c>--sid [UserSID]</c> (the installing user, also when elevated with another admin's
/// credentials); the SID is remembered in <c>HKLM\SOFTWARE\MinControl</c> so uninstall cleans that user even when
/// another admin removes the product.
/// </summary>
internal static class AdminShortcuts
{
    public const string LinkName = "MinControl Connect.lnk";
    public const string LayoutFileName = "TaskbarLayout.xml";
    public const string ConnectExe = "MinControl.Connect.exe";
    private const string PolicyKey = @"Software\Policies\Microsoft\Windows\Explorer";
    private const string ShellFoldersKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
    private const string MarkerValue = "ShortcutUserSid";

    public static int Install(string? sid, string installDir)
    {
        if (!AdminShortcutRules.IsUserSid(sid)) { Console.Error.WriteLine("admin-shortcuts: --sid <S-1-5-21-…> of the installing user is required"); return 2; }
        var connect = Path.Combine(installDir, ConnectExe);
        var rc = 0;

        try
        {
            if (DesktopFor(sid!) is { } desktop)
            {
                Directory.CreateDirectory(desktop);
                var lnk = Path.Combine(desktop, LinkName);
                CreateLink(lnk, connect, installDir, "Kết nối máy này với điện thoại của cha mẹ (MinControl)");
                Console.WriteLine("desktop shortcut: " + lnk);
            }
            else Console.WriteLine("desktop shortcut: profile of " + sid + " not found");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or COMException or ArgumentException)
        {
            Console.Error.WriteLine("desktop shortcut failed: " + e.Message);
            rc = 1;
        }

        try { PinToTaskbar(sid!, installDir); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Console.Error.WriteLine("taskbar pin policy failed: " + e.Message);
            rc = 1;
        }

        try
        {
            using var k = Registry.LocalMachine.CreateSubKey(EnrollStatus.RegPath);
            k.SetValue(MarkerValue, sid!);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
        return rc;
    }

    public static int Remove(string? sid, string installDir)
    {
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (AdminShortcutRules.IsUserSid(sid)) sids.Add(sid!);
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(EnrollStatus.RegPath, writable: true);
            if (k?.GetValue(MarkerValue) is string marked && AdminShortcutRules.IsUserSid(marked)) sids.Add(marked);
            k?.DeleteValue(MarkerValue, throwOnMissingValue: false);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }

        var ourLayout = Path.Combine(installDir, LayoutFileName);
        foreach (var s in sids)
        {
            try
            {
                if (DesktopFor(s) is { } desktop)
                {
                    var lnk = Path.Combine(desktop, LinkName);
                    if (File.Exists(lnk)) { File.Delete(lnk); Console.WriteLine("removed " + lnk); }
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { Console.Error.WriteLine("desktop shortcut: " + e.Message); }

            try
            {
                using var policy = Registry.Users.OpenSubKey(s + @"\" + PolicyKey, writable: true);
                if (policy is not null && policy.GetValue("StartLayoutFile") is string f && !string.IsNullOrWhiteSpace(f)
                    && AdminShortcutRules.PolicyIsFreeOrOurs(f, ourLayout))
                {
                    policy.DeleteValue("StartLayoutFile", throwOnMissingValue: false);
                    policy.DeleteValue("LockedStartLayout", throwOnMissingValue: false);
                    Console.WriteLine("removed taskbar layout policy of " + s);
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                Console.Error.WriteLine("taskbar layout policy: " + e.Message);
            }
        }
        return 0;
    }

    private static void PinToTaskbar(string sid, string installDir)
    {
        if (!AdminShortcutRules.TaskbarPolicySupported(Environment.OSVersion.Version))
        {
            Console.WriteLine("taskbar pin: Windows 10 has no per-user taskbar-only layout policy; skipped (desktop + Start menu shortcuts only)");
            return;
        }
        var layout = Path.Combine(installDir, LayoutFileName);
        if (!File.Exists(layout)) { Console.WriteLine("taskbar pin: " + layout + " missing; skipped"); return; }
        using var hive = Registry.Users.OpenSubKey(sid);
        if (hive is null) { Console.WriteLine("taskbar pin: profile of " + sid + " is not loaded; skipped"); return; }
        using var policy = Registry.Users.CreateSubKey(sid + @"\" + PolicyKey, writable: true);
        if (!AdminShortcutRules.PolicyIsFreeOrOurs(policy.GetValue("StartLayoutFile") as string, layout))
        {
            Console.WriteLine("taskbar pin: the user already has a Start Layout policy; left unchanged");
            return;
        }
        policy.SetValue("StartLayoutFile", layout, RegistryValueKind.ExpandString);
        policy.SetValue("LockedStartLayout", 1, RegistryValueKind.DWord);
        Console.WriteLine("taskbar pin: layout policy set for " + sid + " (applies at next sign-in)");
    }

    private static string? DesktopFor(string sid)
    {
        if (!SystemTools.UserProfiles().TryGetValue(sid, out var profile)) return null;
        string? shellFolder = null;
        try
        {
            using var k = Registry.Users.OpenSubKey(sid + @"\" + ShellFoldersKey);
            shellFolder = k?.GetValue("Desktop", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
        return AdminShortcutRules.DesktopOf(profile, shellFolder);
    }

    // ------------------------------------------------------------------ IShellLink

    private static void CreateLink(string lnkPath, string target, string workingDir, string description)
    {
        var link = (IShellLinkW)new ShellLink();
        try
        {
            link.SetPath(target);
            link.SetWorkingDirectory(workingDir);
            link.SetDescription(description);
            link.SetIconLocation(target, 0);
            ((IPersistFile)link).Save(lnkPath, true);
        }
        finally { Marshal.FinalReleaseComObject(link); }
    }

    [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
    private class ShellLink { }

    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("000214F9-0000-0000-C000-000000000046")]
    private interface IShellLinkW
    {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszFile, int cch, IntPtr pfd, int fFlags);
        void GetIDList(out IntPtr ppidl);
        void SetIDList(IntPtr pidl);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszName, int cch);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszDir, int cch);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszArgs, int cch);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
        void GetHotkey(out short pwHotkey);
        void SetHotkey(short wHotkey);
        void GetShowCmd(out int piShowCmd);
        void SetShowCmd(int iShowCmd);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] System.Text.StringBuilder pszIconPath, int cch, out int piIcon);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, int dwReserved);
        void Resolve(IntPtr hwnd, int fFlags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
    }
}
