using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace MinControl.Monitoring.Inventory;

/// <summary>One Uninstall-key product (already filtered).</summary>
internal sealed record RawUninstall(string Name, string? Version, string? Publisher, string? InstallDir, string? Exe);
/// <summary>A Start-menu shortcut resolved to its target exe.</summary>
internal sealed record RawShortcut(string Name, string TargetExe);
/// <summary>A per-user AppX package.</summary>
internal sealed record RawAppx(string PackageName, string? DisplayName, string? Version, string? InstallDir, string? Publisher);
/// <summary>An exe the user actually ran in the last 7 days.</summary>
internal sealed record SeenExe(string ExePath, int Minutes7d, DateTimeOffset? LastUsed);

internal sealed record AppEntry(string Id, string Name, string Kind, string? Publisher, string? Version, string? InstallDir,
    string? Exe, string? ExePath, DateTimeOffset? LastUsed, int? Minutes7d, string Category);

/// <summary>Injectable data sources so merge/filter logic is testable without registry or disk.</summary>
internal interface IInventorySources
{
    IReadOnlyList<RawUninstall> Uninstalls(string sid);
    IReadOnlyList<RawShortcut> Shortcuts(string sid);
    IReadOnlyList<RawAppx> Appx(string sid);
}

internal static class InventoryIds
{
    public static string Id(string kind, string key)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(kind + "|" + key))).ToLowerInvariant();

    public static string NormPath(string p)
        => p.Trim().Trim('"').Replace('/', '\\').TrimEnd('\\').ToLowerInvariant();
}

/// <summary>Parses one Uninstall subkey; <paramref name="read"/> returns a registry value or null.</summary>
internal static class UninstallParser
{
    public static RawUninstall? Parse(Func<string, object?> read)
    {
        if (read("DisplayName") is not string name || string.IsNullOrWhiteSpace(name)) return null;
        name = name.Trim();
        if (read("SystemComponent") is int sc && sc == 1) return null;
        if (read("ParentKeyName") is string { Length: > 0 }) return null;
        if (read("ReleaseType") is string rt && (rt.Contains("Update", StringComparison.OrdinalIgnoreCase)
            || rt.Contains("Hotfix", StringComparison.OrdinalIgnoreCase) || rt.Contains("Security", StringComparison.OrdinalIgnoreCase)))
            return null;
        if (Regex.IsMatch(name, @"\bKB\d{6,8}\b", RegexOptions.IgnoreCase)) return null;
        if (Regex.IsMatch(name, @"^(Security|Hotfix|Update) (Update )?for\b", RegexOptions.IgnoreCase)) return null;

        string? icon = (read("DisplayIcon") as string)?.Trim();
        string? exe = null;
        if (!string.IsNullOrEmpty(icon))
        {
            if (icon.StartsWith('"')) { int e = icon.IndexOf('"', 1); icon = e > 0 ? icon[1..e] : icon.Trim('"'); }
            else { int c = icon.LastIndexOf(','); if (c > 0 && int.TryParse(icon[(c + 1)..].Trim(), out _)) icon = icon[..c]; }
            icon = icon.Trim().Trim('"');
            if (icon.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && icon.Length > 3 && icon[1] == ':') exe = icon;
        }
        string? dir = (read("InstallLocation") as string)?.Trim().Trim('"');
        if (string.IsNullOrEmpty(dir)) dir = null;
        if (dir is null && exe is not null) dir = Path.GetDirectoryName(exe);
        return new RawUninstall(name, read("DisplayVersion") as string, (read("Publisher") as string)?.Trim(), dir, exe);
    }
}

/// <summary>Built-in publisher/name/path hints. Order matters: Zalo (VNG) must be social, not game.</summary>
internal static class AppCategorizer
{
    private static readonly (string Category, Regex Rx)[] Rules =
    [
        ("system", Make("webview2", "microsoft visual c\\+\\+", "\\.net", "redistributable", "directx", "windows sdk")),
        ("social", Make("zalo", "discord", "messenger", "telegram", "facebook", "whatsapp", "viber", "skype", "instagram", "wechat", "snapchat", "twitter")),
        ("study", Make("microsoft office", "microsoft word", "excel", "powerpoint", "onenote", "outlook", "microsoft teams", "teams", "zoom", "google classroom", "notion", "anki", "duolingo", "libreoffice", "foxit", "adobe acrobat", "acrobat reader", "geogebra")),
        ("video", Make("youtube", "netflix", "tiktok", "vlc", "videolan", "disney", "kmplayer", "potplayer", "twitch", "prime video", "capcut", "movies & tv")),
        ("browser", Make("google chrome", "chrome", "firefox", "mozilla", "opera", "brave", "coc coc", "cốc cốc", "coccoc", "vivaldi", "microsoft edge", "msedge")),
        ("game", Make("valve", "steam", "steamapps", "riot", "riot games", "valorant", "league of legends", "epic games", "epicgameslauncher", "mojang", "minecraft", "roblox",
            "mihoyo", "hoyoverse", "genshin", "honkai", "garena", "vng", "ubisoft", "uplay", "ea", "electronic arts", "blizzard", "battle.net", "tencent", "supercell",
            "nexon", "rockstar", "2k", "bandai namco", "gog galaxy", "ea desktop", "wargaming", "pubg", "krafton", "lien quan", "liên quân", "free fire", "fortnite", "osu")),
        ("system", Make("windows", "microsoft visual c\\+\\+", "\\.net", "directx", "webview2", "nvidia", "intel", "realtek", "amd", "driver", "runtime", "redistributable", "microsoft corporation")),
    ];

    private static Regex Make(params string[] words)
        => new(@"(?<![\p{L}\p{N}])(?:" + string.Join("|", words.Select(w => w.Contains('\\') ? w : Regex.Escape(w))) + @")(?![\p{L}\p{N}])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static string Category(string name, string? publisher, string? path)
    {
        // The name decides first, then publisher, then path, so that e.g. "Zalo" by VNG is not a game.
        foreach (var field in new[] { name, publisher, path })
        {
            if (string.IsNullOrEmpty(field)) continue;
            foreach (var (cat, rx) in Rules)
            {
                if (cat == "system" && field == path && !IsWindowsPath(path)) continue;
                if (rx.IsMatch(field)) return cat;
            }
        }
        return "other";
    }

    private static bool IsWindowsPath(string? p)
        => p is not null && p.Replace('/', '\\').Contains("\\windows\\", StringComparison.OrdinalIgnoreCase);
}
