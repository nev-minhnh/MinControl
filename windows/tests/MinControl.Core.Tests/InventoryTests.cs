using MinControl.Monitoring.Inventory;
using Xunit;

namespace MinControl.Core.Tests;

public class InventoryTests
{
    private static Func<string, object?> Reg(Dictionary<string, object?> d) => k => d.GetValueOrDefault(k);
    private static string? NoPub(string _) => null;

    [Fact]
    public void Uninstall_filters_system_components_updates_and_nameless()
    {
        Assert.Null(UninstallParser.Parse(Reg(new() { ["DisplayName"] = "X", ["SystemComponent"] = 1 })));
        Assert.Null(UninstallParser.Parse(Reg(new() { ["DisplayName"] = "X", ["ParentKeyName"] = "Office" })));
        Assert.Null(UninstallParser.Parse(Reg(new() { ["DisplayName"] = "Update for Windows (KB5001234)" })));
        Assert.Null(UninstallParser.Parse(Reg(new() { ["DisplayName"] = "Foo", ["ReleaseType"] = "Hotfix" })));
        Assert.Null(UninstallParser.Parse(Reg(new() { ["Publisher"] = "Nobody" })));
        Assert.Null(UninstallParser.Parse(Reg(new() { ["DisplayName"] = "  " })));
        var ok = UninstallParser.Parse(Reg(new()
        {
            ["DisplayName"] = "Zalo", ["Publisher"] = "VNG Corp", ["DisplayVersion"] = "1.2",
            ["DisplayIcon"] = "\"C:\\Program Files\\Zalo\\Zalo.exe\",0",
        }));
        Assert.NotNull(ok);
        Assert.Equal(@"C:\Program Files\Zalo\Zalo.exe", ok!.Exe);
        Assert.Equal(@"C:\Program Files\Zalo", ok.InstallDir);
    }

    [Fact]
    public void Id_is_stable_and_path_case_insensitive()
    {
        Assert.Equal(InventoryIds.Id("win32", InventoryIds.NormPath(@"C:\Games\Foo\")), InventoryIds.Id("win32", InventoryIds.NormPath(@"c:/games/foo")));
        Assert.NotEqual(InventoryIds.Id("win32", "a"), InventoryIds.Id("appx", "a"));
        Assert.Equal(64, InventoryIds.Id("seen", "x").Length);
    }

    [Fact]
    public void Merge_dedupes_shortcut_and_seen_into_uninstall_entry()
    {
        var u = new[] { new RawUninstall("Cool Game", "1.0", "Garena", @"C:\Games\Cool", null) };
        var sc = new[] { new RawShortcut("Cool Game", @"C:\Games\Cool\cool.exe"), new RawShortcut("Uninstall Cool Game", @"C:\Games\Cool\unins.exe") };
        var seen = new[]
        {
            new SeenExe(@"C:\Games\Cool\cool.exe", 40, DateTimeOffset.Parse("2026-11-20T10:00:00Z")),
            new SeenExe(@"C:\Games\Cool\launcher.exe", 5, DateTimeOffset.Parse("2026-11-21T10:00:00Z")),
            new SeenExe(@"C:\Tools\thing.exe", 3, null),
            new SeenExe(@"C:\Windows\System32\svchost.exe", 99, null),
        };
        var apps = InventoryMerger.Merge(u, sc, [], seen, NoPub, @"C:\Windows");
        Assert.Equal(2, apps.Count);
        var game = apps.Single(a => a.Kind == "win32");
        Assert.Equal(45, game.Minutes7d);
        Assert.Equal(@"C:\Games\Cool\cool.exe", game.ExePath);
        Assert.Equal("game", game.Category);
        Assert.Equal(DateTimeOffset.Parse("2026-11-21T10:00:00Z"), game.LastUsed);
        var thing = apps.Single(a => a.Kind == "seen");
        Assert.Equal("thing", thing.Name);
        Assert.Equal(game.Id, apps[0].Id);  // sorted by minutes
    }

    [Fact]
    public void Id_does_not_change_when_exe_is_discovered_later()
    {
        var u = new[] { new RawUninstall("Foo", null, null, @"C:\Foo", null) };
        var a = InventoryMerger.Merge(u, [], [], [], NoPub).Single();
        var b = InventoryMerger.Merge(u, [new RawShortcut("Foo", @"C:\Foo\foo.exe")], [], [new SeenExe(@"C:\Foo\foo.exe", 1, null)], NoPub).Single();
        Assert.Equal(a.Id, b.Id);
        Assert.Null(a.ExePath);
        Assert.Equal("foo.exe", b.Exe);
    }

    [Fact]
    public void Shortcut_only_app_and_publisher_from_signature()
    {
        var apps = InventoryMerger.Merge([], [new RawShortcut("Tool", @"D:\T\tool.exe")], [], [], p => "Acme Ltd");
        var t = Assert.Single(apps);
        Assert.Equal("Acme Ltd", t.Publisher);
        Assert.Equal(@"D:\T", t.InstallDir);
    }

    [Fact]
    public void Appx_gets_friendly_name_and_is_matched_by_dir()
    {
        var apps = InventoryMerger.Merge([], [], [new RawAppx("Microsoft.WindowsCalculator", "ms-resource:AppName", "11.0", @"C:\Program Files\WindowsApps\calc_11", null)],
            [new SeenExe(@"C:\Program Files\WindowsApps\calc_11\calc.exe", 7, null)], NoPub);
        var a = Assert.Single(apps);
        Assert.Equal("appx", a.Kind);
        Assert.Equal("WindowsCalculator", a.Name);
        Assert.Equal(7, a.Minutes7d);
    }

    [Theory]
    [InlineData("Minecraft Launcher", "Mojang", "game")]
    [InlineData("Roblox Player", "Roblox Corporation", "game")]
    [InlineData("Genshin Impact", "miHoYo", "game")]
    [InlineData("Steam", "Valve Corporation", "game")]
    [InlineData("Zalo", "VNG Corporation", "social")]
    [InlineData("Discord", null, "social")]
    [InlineData("Google Chrome", "Google LLC", "browser")]
    [InlineData("VLC media player", "VideoLAN", "video")]
    [InlineData("Microsoft Teams", "Microsoft Corporation", "study")]
    [InlineData("Microsoft Visual C++ 2015-2022 Redistributable (x64)", "Microsoft Corporation", "system")]
    [InlineData("Microsoft Edge WebView2 Runtime", "Microsoft Corporation", "system")]
    [InlineData("Notepad++", "Don Ho", "other")]
    public void Category_hints(string name, string? publisher, string expected)
        => Assert.Equal(expected, AppCategorizer.Category(name, publisher, null));

    [Fact]
    public void Ledger_counts_last_7_days_and_persists()
    {
        var file = Path.Combine(Path.GetTempPath(), "mc-inv-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var now = DateTimeOffset.Parse("2026-11-22T12:00:00Z");
            var l = new UsageLedger(file);
            l.AddActive("S-1", @"C:\a.exe", 600, now.AddDays(-10));
            l.AddActive("S-1", @"C:\a.exe", 120, now.AddDays(-1));
            l.AddActive("S-1", @"C:\a.exe", 60, now);
            l.Touch("S-1", @"C:\b.exe", now);
            l.Save();
            var l2 = new UsageLedger(file);
            var snap = l2.Snapshot("S-1", now);
            Assert.Equal(3, snap.Single(s => s.ExePath == @"C:\a.exe").Minutes7d);
            Assert.Equal(0, snap.Single(s => s.ExePath == @"C:\b.exe").Minutes7d);
            Assert.Empty(l2.Snapshot("S-2", now));
        }
        finally { try { File.Delete(file); } catch { } }
    }
}
