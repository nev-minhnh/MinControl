using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Policy;

namespace MinControl.NetGuard.Wfp;

/// <summary>
/// Turns <c>netExemptApps</c> (<see cref="AppMatch"/>) into concrete executable paths for FWPM_CONDITION_ALE_APP_ID.
/// WFP matches by image path, so:
/// <list type="bullet">
/// <item><c>path</c> without wildcards (env vars expanded) → that file, if it exists;</item>
/// <item><c>path</c> with wildcards in the file-name part only → files in that directory matching the pattern;</item>
/// <item><c>exe</c> only / <c>publisher</c> only → cannot be mapped to a WFP app id; skipped with a warning
///   (TODO: resolve via the Monitoring stream's observed process paths);</item>
/// <item><c>sha256</c> given → each candidate must hash to it (protects against renamed binaries);</item>
/// <item><c>exe</c> given together with <c>path</c> → file name must also match the exe glob.</item>
/// </list>
/// </summary>
public sealed class ExemptAppResolver
{
    private readonly ILogger _log;

    public ExemptAppResolver(ILogger<ExemptAppResolver>? log = null) => _log = (ILogger?)log ?? NullLogger.Instance;

    public IReadOnlyList<string> Resolve(IEnumerable<AppMatch>? matches)
    {
        var result = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        if (matches is null) return [];
        foreach (var m in matches)
        {
            if (string.IsNullOrWhiteSpace(m.Path))
            {
                _log.LogWarning("netExemptApps entry without 'path' cannot be enforced by WFP (exe={Exe}); skipped", m.Exe);
                continue;
            }
            foreach (var candidate in Candidates(Environment.ExpandEnvironmentVariables(m.Path)))
            {
                if (m.Exe is not null && !GlobMatch(m.Exe, Path.GetFileName(candidate))) continue;
                if (m.Sha256 is not null && !HashMatches(candidate, m.Sha256)) continue;
                result.Add(Path.GetFullPath(candidate));
            }
        }
        return result.ToList();
    }

    private IEnumerable<string> Candidates(string path)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            var name = Path.GetFileName(path);
            if (string.IsNullOrEmpty(dir) || string.IsNullOrEmpty(name)) return [];
            if (dir.IndexOfAny(['*', '?']) >= 0)
            {
                _log.LogWarning("netExemptApps path {Path}: wildcards in directories are not supported", path);
                return [];
            }
            if (name.IndexOfAny(['*', '?']) < 0) return File.Exists(path) ? [path] : [];
            return Directory.Exists(dir) ? Directory.EnumerateFiles(dir, name).Take(64).ToList() : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            _log.LogWarning(ex, "netExemptApps path {Path} not resolvable", path);
            return [];
        }
    }

    private static bool HashMatches(string file, string sha256)
    {
        try
        {
            using var fs = File.OpenRead(file);
            return string.Equals(Convert.ToHexStringLower(SHA256.HashData(fs)), sha256, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>Case-insensitive glob with * and ?.</summary>
    public static bool GlobMatch(string pattern, string text)
    {
        int p = 0, t = 0, star = -1, mark = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || char.ToLowerInvariant(pattern[p]) == char.ToLowerInvariant(text[t]))) { p++; t++; }
            else if (p < pattern.Length && pattern[p] == '*') { star = p++; mark = t; }
            else if (star >= 0) { p = star + 1; t = ++mark; }
            else return false;
        }
        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }
}
