using System.Text.RegularExpressions;

namespace MinControl.Setup;

/// <summary>Pure rules of <c>AdminShortcuts</c> (unit-tested).</summary>
internal static partial class AdminShortcutRules
{
    [GeneratedRegex(@"^S-1-5-21(-\d+){4}$", RegexOptions.CultureInvariant)]
    private static partial Regex UserSidPattern();

    public static bool IsUserSid(string? sid) => sid is not null && UserSidPattern().IsMatch(sid);

    /// <summary>Windows 11 = build 22000 or later (the taskbar section of the Start Layout policy applies there).</summary>
    public static bool TaskbarPolicySupported(Version os) => os.Major == 10 && os.Build >= 22000;

    /// <summary>The user's desktop folder: the "Desktop" entry of their User Shell Folders (OneDrive redirection etc.,
    /// %USERPROFILE% expanded to <paramref name="profile"/>), else <c>&lt;profile&gt;\Desktop</c>.</summary>
    public static string DesktopOf(string profile, string? userShellFolderValue)
    {
        if (string.IsNullOrWhiteSpace(userShellFolderValue)) return Path.Combine(profile, "Desktop");
        var v = Regex.Replace(userShellFolderValue, "%USERPROFILE%", profile.Replace("$", "$$"), RegexOptions.IgnoreCase);
        return Environment.ExpandEnvironmentVariables(v);
    }

    /// <summary>True when the Start Layout policy may be (re)written: none set, or it is ours.</summary>
    public static bool PolicyIsFreeOrOurs(string? currentStartLayoutFile, string ourFile) =>
        string.IsNullOrWhiteSpace(currentStartLayoutFile)
        || string.Equals(Environment.ExpandEnvironmentVariables(currentStartLayoutFile).Trim(), ourFile, StringComparison.OrdinalIgnoreCase);
}
