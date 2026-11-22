namespace MinControl.Monitoring.Inventory;

/// <summary>Pure merge of the four sources into one app list per user (API.md §11): by exe path / installDir.</summary>
internal static class InventoryMerger
{
    private sealed class B
    {
        public required string Kind, Key, Name;
        public string? Publisher, Version, InstallDir, Exe;
        public DateTimeOffset? LastUsed;
        public int Minutes;
        public bool HasUsage;
        public int BestExeMinutes = -1;
    }

    public static IReadOnlyList<AppEntry> Merge(
        IEnumerable<RawUninstall> uninstalls, IEnumerable<RawShortcut> shortcuts, IEnumerable<RawAppx> appx,
        IEnumerable<SeenExe> seen, Func<string, string?> publisherOf, string? windowsDir = null)
    {
        var list = new List<B>();
        var byKey = new Dictionary<string, B>();

        foreach (var u in uninstalls)
        {
            string key = u.InstallDir is { Length: > 0 } d ? InventoryIds.NormPath(d)
                : u.Exe is { Length: > 0 } e ? InventoryIds.NormPath(e) : "name:" + u.Name.ToLowerInvariant();
            if (byKey.TryGetValue("win32|" + key, out var dup)) { dup.Version ??= u.Version; dup.Publisher ??= u.Publisher; continue; }
            var b = new B { Kind = "win32", Key = key, Name = u.Name, Publisher = u.Publisher, Version = u.Version, InstallDir = u.InstallDir, Exe = u.Exe };
            byKey["win32|" + key] = b; list.Add(b);
        }

        foreach (var a in appx)
        {
            string key = a.PackageName.ToLowerInvariant();
            if (byKey.ContainsKey("appx|" + key)) continue;
            var name = a.DisplayName is { Length: > 0 } dn && !dn.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase) && !dn.StartsWith("@{", StringComparison.Ordinal)
                ? dn : FriendlyPackageName(a.PackageName);
            var b = new B { Kind = "appx", Key = key, Name = name, Publisher = a.Publisher, Version = a.Version, InstallDir = a.InstallDir };
            byKey["appx|" + key] = b; list.Add(b);
        }

        var win32 = list.Where(x => x.Kind == "win32").ToList();
        B? Owner(string exe)
        {
            string n = InventoryIds.NormPath(exe);
            B? best = null; int bestLen = -1;
            foreach (var b in win32.Concat(list.Where(x => x.Kind == "appx")))
            {
                if (b.Exe is not null && InventoryIds.NormPath(b.Exe) == n) return b;
                if (b.InstallDir is { Length: > 0 } d)
                {
                    var nd = InventoryIds.NormPath(d) + "\\";
                    if (n.StartsWith(nd, StringComparison.Ordinal) && nd.Length > bestLen) { best = b; bestLen = nd.Length; }
                }
            }
            return best;
        }

        foreach (var s in shortcuts)
        {
            if (!s.TargetExe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
            if (s.Name.Contains("uninstall", StringComparison.OrdinalIgnoreCase)) continue;
            string key = InventoryIds.NormPath(s.TargetExe);
            var owner = Owner(s.TargetExe);
            if (owner is not null) { owner.Exe ??= s.TargetExe; continue; }
            if (byKey.ContainsKey("win32|" + key)) continue;
            var b = new B { Kind = "win32", Key = key, Name = s.Name, InstallDir = Path.GetDirectoryName(s.TargetExe), Exe = s.TargetExe };
            byKey["win32|" + key] = b; list.Add(b); win32.Add(b);
        }

        foreach (var s in seen)
        {
            if (windowsDir is not null && s.ExePath.StartsWith(windowsDir.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)) continue;
            var owner = Owner(s.ExePath);
            if (owner is null)
            {
                string key = InventoryIds.NormPath(s.ExePath);
                owner = new B { Kind = "seen", Key = key, Name = Path.GetFileNameWithoutExtension(s.ExePath), Exe = s.ExePath };
                byKey["seen|" + key] = owner; list.Add(owner);
            }
            owner.HasUsage = true;
            owner.Minutes += s.Minutes7d;
            if (s.LastUsed is { } lu && (owner.LastUsed is null || lu > owner.LastUsed)) owner.LastUsed = lu;
            if (s.Minutes7d > owner.BestExeMinutes) { owner.BestExeMinutes = s.Minutes7d; if (owner.Kind != "seen" && (owner.Exe is null || s.Minutes7d > 0)) owner.Exe = s.ExePath; }
        }

        var result = new List<AppEntry>(list.Count);
        foreach (var b in list)
        {
            string? exePath = b.Exe;
            string? publisher = b.Publisher;
            if (string.IsNullOrWhiteSpace(publisher) && exePath is not null) { try { publisher = publisherOf(exePath); } catch { } }
            result.Add(new AppEntry(InventoryIds.Id(b.Kind, b.Key), b.Name, b.Kind, Nz(publisher), Nz(b.Version), Nz(b.InstallDir),
                exePath is null ? null : Path.GetFileName(exePath), exePath, b.LastUsed, b.HasUsage ? b.Minutes : null,
                AppCategorizer.Category(b.Name, publisher, exePath ?? b.InstallDir)));
        }
        return result
            .OrderByDescending(a => a.Minutes7d ?? 0).ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string? Nz(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    /// <summary>"Microsoft.WindowsCalculator" → "WindowsCalculator" (best effort when DisplayName is a resource ref).</summary>
    internal static string FriendlyPackageName(string package)
    {
        int i = package.LastIndexOf('.');
        return i > 0 && i < package.Length - 1 ? package[(i + 1)..] : package;
    }
}
