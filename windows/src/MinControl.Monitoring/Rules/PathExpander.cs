using System.Text;

namespace MinControl.Monitoring.Rules;

/// <summary>
/// Expands <c>%VAR%</c> references in policy path globs. The agent runs as LocalSystem, so per-user
/// variables (<c>%USERPROFILE%</c>, <c>%LOCALAPPDATA%</c>, <c>%APPDATA%</c>, <c>%TEMP%</c>, <c>%TMP%</c>,
/// <c>%HOMEDRIVE%%HOMEPATH%</c>) are resolved against the managed user's profile path, never the
/// service's own profile. Everything else uses machine-level environment values.
/// Unknown variables are left verbatim (so they never match accidentally).
/// </summary>
public static class PathExpander
{
    public static string Expand(string pattern, string? profilePath, Func<string, string?>? machineVar = null)
    {
        if (pattern.IndexOf('%') < 0) return Normalize(pattern);
        machineVar ??= DefaultMachineVar;

        var sb = new StringBuilder(pattern.Length + 64);
        int i = 0;
        while (i < pattern.Length)
        {
            int start = pattern.IndexOf('%', i);
            if (start < 0) { sb.Append(pattern, i, pattern.Length - i); break; }
            int end = pattern.IndexOf('%', start + 1);
            if (end < 0) { sb.Append(pattern, i, pattern.Length - i); break; }

            sb.Append(pattern, i, start - i);
            string name = pattern.Substring(start + 1, end - start - 1);
            string? value = name.Length == 0 ? null : UserVar(name, profilePath) ?? machineVar(name);
            if (value is null)
            {
                // keep "%NAME" and continue scanning from the closing '%' (it may open the next var)
                sb.Append(pattern, start, end - start);
                i = end;
                continue;
            }
            sb.Append(value.TrimEnd('\\', '/'));
            i = end + 1;
        }
        return Normalize(sb.ToString());
    }

    private static string? UserVar(string name, string? profile)
    {
        if (profile is null) return null;
        profile = profile.TrimEnd('\\', '/');
        return name.ToUpperInvariant() switch
        {
            "USERPROFILE" => profile,
            "LOCALAPPDATA" => profile + @"\AppData\Local",
            "APPDATA" => profile + @"\AppData\Roaming",
            "TEMP" or "TMP" => profile + @"\AppData\Local\Temp",
            "HOMEPATH" => profile.Length > 2 && profile[1] == ':' ? profile[2..] : profile,
            "HOMEDRIVE" => profile.Length > 2 && profile[1] == ':' ? profile[..2] : null,
            "ONEDRIVE" => profile + @"\OneDrive",
            _ => null,
        };
    }

    private static string? DefaultMachineVar(string name)
    {
        // Environment of the LocalSystem service = machine environment for these.
        var v = Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Machine)
                ?? Environment.GetEnvironmentVariable(name);
        return string.IsNullOrEmpty(v) ? null : v;
    }

    internal static string Normalize(string path) => path.Replace('/', '\\');
}
