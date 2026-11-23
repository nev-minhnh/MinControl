namespace MinControl.Setup;

/// <summary>Local-state wipe used by a fresh install (see <c>install --fresh</c>).</summary>
public static class SetupWipe
{
    /// <summary>Folder under the data root that survives a fresh-install wipe: live category lists and the shipped
    /// seed (<c>categories\seed</c>, laid down by the MSI before the Setup custom action runs).</summary>
    public const string KeptFolder = "categories";

    /// <summary>
    /// Deletes everything inside <paramref name="root"/> (state.db, device.key, screenshots, logs, caches, config,
    /// enrol status, markers, ...) except the <see cref="KeptFolder"/> directory. The root itself stays.
    /// Best effort per entry; returns the entries that could not be deleted.
    /// </summary>
    public static IReadOnlyList<string> WipeExceptCategories(string root)
    {
        var failed = new List<string>();
        if (!Directory.Exists(root)) return failed;
        foreach (var entry in Directory.EnumerateFileSystemEntries(root))
        {
            var name = System.IO.Path.GetFileName(entry);
            if (string.Equals(name, KeptFolder, StringComparison.OrdinalIgnoreCase) && Directory.Exists(entry)) continue;
            try
            {
                if (Directory.Exists(entry)) Directory.Delete(entry, recursive: true);
                else File.Delete(entry);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                failed.Add(entry);
            }
        }
        return failed;
    }
}
