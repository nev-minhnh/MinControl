namespace MinControl.Browser.History;

/// <summary>A browser profile's History database. <see cref="Browser"/> is msedge | chrome.</summary>
public sealed record HistoryFile(string Browser, string Profile, string Path);

/// <summary>Finds the History databases of a user; injectable for tests.</summary>
public interface IHistoryFileLocator
{
    IReadOnlyList<HistoryFile> Locate(string sid, string profilePath);
}

/// <summary>
/// &lt;profile&gt;\AppData\Local\{Microsoft\Edge|Google\Chrome}\User Data\{Default|Profile N}\History.
/// </summary>
public sealed class HistoryFileLocator : IHistoryFileLocator
{
    private static readonly (string Browser, string Relative)[] Roots =
    [
        ("msedge", @"AppData\Local\Microsoft\Edge\User Data"),
        ("chrome", @"AppData\Local\Google\Chrome\User Data"),
    ];

    public IReadOnlyList<HistoryFile> Locate(string sid, string profilePath)
    {
        var list = new List<HistoryFile>();
        foreach (var (browser, rel) in Roots)
        {
            string root = Path.Combine(profilePath, rel);
            IEnumerable<string> dirs;
            try
            {
                if (!Directory.Exists(root)) continue;
                dirs = Directory.EnumerateDirectories(root).ToList();
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { continue; }
            foreach (var dir in dirs)
            {
                string name = Path.GetFileName(dir);
                if (!IsProfileDir(name)) continue;
                string history = Path.Combine(dir, "History");
                if (File.Exists(history)) list.Add(new HistoryFile(browser, name, history));
            }
        }
        return list;
    }

    internal static bool IsProfileDir(string name) =>
        name == "Default" ||
        (name.StartsWith("Profile ", StringComparison.Ordinal) && name.Length > 8 && name.AsSpan(8).IndexOfAnyExceptInRange('0', '9') < 0);
}
