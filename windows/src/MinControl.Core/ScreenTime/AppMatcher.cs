using MinControl.Core.Policy;
using MinControl.Core.Util;

namespace MinControl.Core.ScreenTime;

/// <summary>Facts about an executable that an <see cref="AppMatch"/> can test. Unknown facts never match.</summary>
public sealed record AppFacts(string Path, string? Sha256 = null, string? Publisher = null);

/// <summary>
/// Simple AppMatch evaluator used for screen-time group membership. All properties present in an AppMatch
/// must match (AND). Monitoring has the authoritative matcher (publisher, hashes, user-writable detection);
/// when an <c>IAppMonitor</c> is registered the engine asks it first.
/// </summary>
public static class AppMatcher
{
    public static bool Matches(AppMatch m, AppFacts f)
    {
        if (m.Exe is not null && !Glob.IsMatch(m.Exe, System.IO.Path.GetFileName(f.Path))) return false;
        if (m.Path is not null && !Glob.IsMatch(Environment.ExpandEnvironmentVariables(m.Path), f.Path)) return false;
        if (m.Publisher is not null && (f.Publisher is null || !Glob.IsMatch(m.Publisher, f.Publisher))) return false;
        if (m.Sha256 is not null && (f.Sha256 is null || !string.Equals(m.Sha256, f.Sha256, StringComparison.OrdinalIgnoreCase))) return false;
        if (m.PathUnderUserWritable == true && !IsUserWritable(f.Path)) return false;
        return m.Exe is not null || m.Path is not null || m.Publisher is not null || m.Sha256 is not null || m.PathUnderUserWritable == true;
    }

    /// <summary>First group (policy order) whose match list contains a matching entry.</summary>
    public static string? GroupOf(UserPolicy user, AppFacts f)
    {
        foreach (var (name, g) in user.AppGroups)
            foreach (var m in g.Match)
                if (Matches(m, f)) return name;
        return null;
    }

    /// <summary>Heuristic: under C:\Users\..., any \AppData\ or \Temp\ folder, or %ProgramData% (writable by Users by default).</summary>
    public static bool IsUserWritable(string path)
    {
        var p = path.Replace('/', '\\');
        var users = Environment.GetEnvironmentVariable("SystemDrive") is { Length: > 0 } sd ? sd + "\\Users\\" : "C:\\Users\\";
        if (p.StartsWith(users, StringComparison.OrdinalIgnoreCase)) return true;
        if (p.Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase) || p.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase)) return true;
        var pd = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return pd.Length > 0 && p.StartsWith(pd.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
    }
}
