using MinControl.Core.Policy;
using MinControl.Monitoring.Rules;
using Xunit;

namespace MinControl.Core.Tests;

// Owned by the win-monitor stream: pure rule logic of MinControl.Monitoring (no OS access).
public class MonitoringRuleTests
{
    private const string Sid = "S-1-5-21-1-2-3-1001";
    private const string Profile = @"C:\Users\bin";
    private const string Win = @"C:\Windows";

    private sealed class FakeFacts : IFileFacts
    {
        public readonly Dictionary<string, string> Sha = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, SignatureInfo> Sig = new(StringComparer.OrdinalIgnoreCase);
        public int ShaCalls;

        public string? Sha256(string path) { ShaCalls++; return Sha.GetValueOrDefault(path); }
        public SignatureInfo Signature(string path) => Sig.GetValueOrDefault(path) ?? SignatureInfo.Unsigned;
        public long? SizeBytes(string path) => 1;
    }

    private static WeekdayMap<T> All<T>(T v) => new(v, v, v, v, v, v, v);

    private static UserPolicy Policy(
        IReadOnlyList<AppRule>? rules = null,
        IReadOnlyDictionary<string, AppGroup>? groups = null,
        string newExecutable = "allow",
        IReadOnlyList<string>? browsers = null)
        => new(
            "Bin",
            new ScreenTimePolicy(All(120), All<IReadOnlyList<string>>(["00:00-23:59"]), [5], 60, false, 300),
            groups ?? new Dictionary<string, AppGroup>(),
            rules ?? [],
            newExecutable,
            new WebPolicy("blocklist", [], [], [], true, "strict", browsers ?? ["msedge.exe", "chrome.exe"], []),
            new MonitoringPolicy(true, true, true, true, true, new ScreenshotPolicy(5, true, 1280, 60)));

    private static EvaluationContext Ctx(IReadOnlyCollection<string>? exhausted = null,
        Func<string, string?>? approval = null, Func<string, bool>? removable = null)
        => new()
        {
            Sid = Sid,
            ProfilePath = Profile,
            ExhaustedGroups = exhausted ?? [],
            ExtraUserWritableRoots = [@"C:\Windows\Temp", @"C:\Users\Public"],
            IsRemovableOrNetwork = removable ?? (p => p.StartsWith("E:", StringComparison.OrdinalIgnoreCase)),
            ApprovalFor = approval ?? (_ => null),
            WindowsDir = Win,
            MachineVar = name => name.ToUpperInvariant() switch
            {
                "PROGRAMFILES" => @"C:\Program Files",
                "PROGRAMFILES(X86)" => @"C:\Program Files (x86)",
                "WINDIR" => Win,
                _ => null,
            },
        };

    // ------------------------------------------------------------------ Glob

    [Theory]
    [InlineData("Minecraft*.exe", "MinecraftLauncher.exe", true)]
    [InlineData("minecraft*.exe", "MINECRAFT.EXE", true)]
    [InlineData("Minecraft*.exe", "Minecraft.exe.bak", false)]
    [InlineData("?ame.exe", "game.exe", true)]
    [InlineData("?ame.exe", "ame.exe", false)]
    [InlineData("*", "", true)]
    [InlineData("a*b*c", "aXXbYYc", true)]
    [InlineData("a*b*c", "aXXbYY", false)]
    [InlineData("*.exe", "steam.exe", true)]
    [InlineData("Valve*", "Valve Corp.", true)]
    [InlineData(@"C:\Program Files\*\game.exe", @"c:\program files\Studio\Sub\GAME.exe", true)]
    [InlineData("C:/Games/*.exe", @"C:\Games\x.exe", true)]
    [InlineData("steam.exe", "steam.exe ", false)]
    public void Glob_matches_case_insensitively(string pattern, string text, bool expected)
        => Assert.Equal(expected, Glob.IsMatch(pattern, text));

    [Fact]
    public void Glob_handles_pathological_patterns_quickly()
    {
        var text = new string('a', 2000);
        Assert.False(Glob.IsMatch("*a*a*a*a*a*a*a*b", text));
    }

    [Fact]
    public void PathExpander_uses_managed_user_profile_not_service_profile()
    {
        Assert.Equal(@"C:\Users\bin\AppData\Local\Temp\*.exe", PathExpander.Expand("%TEMP%\\*.exe", Profile, _ => null));
        Assert.Equal(@"C:\Users\bin\AppData\Roaming\x.exe", PathExpander.Expand("%AppData%/x.exe", Profile, _ => null));
        Assert.Equal(@"C:\Program Files\Steam\steam.exe",
            PathExpander.Expand("%ProgramFiles%\\Steam\\steam.exe", Profile, n => n == "ProgramFiles" ? @"C:\Program Files\" : null));
        Assert.Equal(@"%NOPE%\a.exe", PathExpander.Expand("%NOPE%\\a.exe", Profile, _ => null));
        Assert.Equal(@"100%\a.exe", PathExpander.Expand("100%\\a.exe", Profile, _ => null));
    }

    // ------------------------------------------------------------------ AppMatch

    [Fact]
    public void Match_requires_all_present_fields()
    {
        var facts = new FakeFacts();
        facts.Sig[@"C:\Games\hl.exe"] = new SignatureInfo(true, "Valve Corp.");
        var ev = new AppRuleEvaluator(facts);
        Assert.True(ev.Matches(new AppMatch(Exe: "hl.exe", Publisher: "Valve*"), @"C:\Games\hl.exe", Ctx()));
        Assert.False(ev.Matches(new AppMatch(Exe: "hl.exe", Publisher: "Epic*"), @"C:\Games\hl.exe", Ctx()));
        Assert.False(ev.Matches(new AppMatch(), @"C:\Games\hl.exe", Ctx()));   // empty match never matches
    }

    [Fact]
    public void Publisher_match_requires_valid_signature()
    {
        var facts = new FakeFacts();
        facts.Sig[@"C:\x\fake.exe"] = new SignatureInfo(false, "Valve Corp.");
        Assert.False(new AppRuleEvaluator(facts).Matches(new AppMatch(Publisher: "Valve*"), @"C:\x\fake.exe", Ctx()));
    }

    [Fact]
    public void Sha256_match_is_case_insensitive_and_lazy()
    {
        var facts = new FakeFacts();
        facts.Sha[@"C:\x\a.exe"] = new string('a', 64);
        var ev = new AppRuleEvaluator(facts);
        Assert.True(ev.Matches(new AppMatch(Sha256: new string('A', 64)), @"C:\x\a.exe", Ctx()));
        facts.ShaCalls = 0;
        Assert.False(ev.Matches(new AppMatch(Exe: "b.exe", Sha256: new string('a', 64)), @"C:\x\a.exe", Ctx()));
        Assert.Equal(0, facts.ShaCalls); // exe mismatch short-circuits before hashing
    }

    [Theory]
    [InlineData(@"C:\Users\bin\Downloads\game.exe", true)]
    [InlineData(@"C:\Users\bin\AppData\Local\Temp\x.exe", true)]
    [InlineData(@"C:\Users\binary\x.exe", false)]                  // prefix of another profile is not "under"
    [InlineData(@"C:\Windows\Temp\x.exe", true)]
    [InlineData(@"C:\Users\Public\x.exe", true)]
    [InlineData(@"E:\portable\x.exe", true)]                       // removable
    [InlineData(@"\\server\share\x.exe", true)]                    // UNC
    [InlineData(@"C:\Program Files\App\x.exe", false)]
    public void PathUnderUserWritable(string path, bool expected)
        => Assert.Equal(expected, AppRuleEvaluator.IsUnderUserWritable(path, Ctx()));

    [Fact]
    public void Path_glob_expands_env_vars()
    {
        var ev = new AppRuleEvaluator(new FakeFacts());
        Assert.True(ev.Matches(new AppMatch(Path: @"%ProgramFiles%\Steam\*"), @"C:\Program Files\Steam\steam.exe", Ctx()));
        Assert.True(ev.Matches(new AppMatch(Path: @"%LOCALAPPDATA%\Roblox\*"), @"C:\Users\bin\AppData\Local\Roblox\v1\RobloxPlayerBeta.exe", Ctx()));
        Assert.False(ev.Matches(new AppMatch(Path: @"%ProgramFiles%\Steam\*"), @"C:\Program Files (x86)\Steam\steam.exe", Ctx()));
    }

    // ------------------------------------------------------------------ appRules

    [Fact]
    public void First_matching_rule_wins()
    {
        var p = Policy(rules:
        [
            new AppRule("allow", new AppMatch(Exe: "steam.exe")),
            new AppRule("block", new AppMatch(Exe: "*.exe")),
        ]);
        var ev = new AppRuleEvaluator(new FakeFacts());
        Assert.Equal(Verdict.Allow, ev.Evaluate(p, @"C:\Program Files\Steam\steam.exe", Ctx()).Verdict);
        var d = ev.Evaluate(p, @"C:\Program Files\Other\other.exe", Ctx());
        Assert.Equal(Verdict.Block, d.Verdict);
        Assert.Equal("appRules[1]", d.Rule);
    }

    [Fact]
    public void Except_list_skips_rule_and_continues_to_next()
    {
        var sha = new string('b', 64);
        var facts = new FakeFacts();
        facts.Sha[@"C:\Users\bin\Downloads\ok.exe"] = sha;
        var p = Policy(rules:
            [new AppRule("block", new AppMatch(PathUnderUserWritable: true), [new AppMatch(Sha256: sha)])]);
        var ev = new AppRuleEvaluator(facts);

        Assert.Equal(Verdict.Allow, ev.Evaluate(p, @"C:\Users\bin\Downloads\ok.exe", Ctx()).Verdict);
        var blocked = ev.Evaluate(p, @"C:\Users\bin\Downloads\bad.exe", Ctx());
        Assert.Equal(Verdict.Block, blocked.Verdict);
        Assert.Equal("appRules[0]", blocked.Rule);
    }

    [Fact]
    public void Critical_shell_processes_are_never_blocked()
    {
        var p = Policy(rules: [new AppRule("block", new AppMatch(Exe: "*"))]);
        var ev = new AppRuleEvaluator(new FakeFacts());
        Assert.Equal(Verdict.Allow, ev.Evaluate(p, @"C:\Windows\explorer.exe", Ctx()).Verdict);
        // same name outside %windir% gets no protection
        Assert.Equal(Verdict.Block, ev.Evaluate(p, @"C:\Users\bin\explorer.exe", Ctx()).Verdict);
    }

    // ------------------------------------------------------------------ groups

    [Fact]
    public void Exhausted_group_blocks_even_explicitly_allowed_apps()
    {
        var groups = new Dictionary<string, AppGroup>
        {
            ["games"] = new("Games", [new AppMatch(Exe: "Minecraft*.exe")]),
        };
        var p = Policy(rules: [new AppRule("allow", new AppMatch(Exe: "Minecraft*.exe"))], groups: groups);
        var ev = new AppRuleEvaluator(new FakeFacts());
        const string exe = @"C:\Program Files\Minecraft\MinecraftLauncher.exe";

        Assert.Equal("games", ev.GroupOf(p, exe, Ctx()));
        Assert.Equal(Verdict.Allow, ev.Evaluate(p, exe, Ctx()).Verdict);
        var d = ev.Evaluate(p, exe, Ctx(exhausted: ["games"]));
        Assert.Equal(Verdict.Block, d.Verdict);
        Assert.Equal("group:games", d.Rule);
        Assert.Equal(Verdict.Allow, ev.Evaluate(p, @"C:\Program Files\Office\winword.exe", Ctx(exhausted: ["games"])).Verdict);
    }

    [Fact]
    public void GroupOf_is_deterministic_by_key_order()
    {
        var groups = new Dictionary<string, AppGroup>
        {
            ["zeta"] = new("Z", [new AppMatch(Exe: "*.exe")]),
            ["alpha"] = new("A", [new AppMatch(Exe: "game.exe")]),
        };
        Assert.Equal("alpha", new AppRuleEvaluator(new FakeFacts()).GroupOf(Policy(groups: groups), @"C:\g\game.exe", Ctx()));
    }

    // ------------------------------------------------------------------ browsers

    [Fact]
    public void Non_allowed_browsers_are_blocked()
    {
        var facts = new FakeFacts();
        facts.Sig[@"C:\Program Files\Google\Chrome\Application\chrome.exe"] = new SignatureInfo(true, "Google LLC");
        facts.Sig[@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"] = new SignatureInfo(true, "Microsoft Corporation");
        var ev = new AppRuleEvaluator(facts);
        var edgeOnly = Policy(browsers: ["msedge.exe"]);

        Assert.Equal(Verdict.Allow, ev.Evaluate(edgeOnly, @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", Ctx()).Verdict);
        Assert.Equal("allowedBrowsers", ev.Evaluate(edgeOnly, @"C:\Program Files\Google\Chrome\Application\chrome.exe", Ctx()).Rule);
        Assert.Equal("allowedBrowsers", ev.Evaluate(edgeOnly, @"C:\Program Files\Mozilla Firefox\firefox.exe", Ctx()).Rule);
        Assert.Equal("allowedBrowsers", ev.Evaluate(edgeOnly, @"C:\Users\bin\AppData\Local\CocCoc\Browser\Application\browser.exe", Ctx()).Rule);
        Assert.Equal("allowedBrowsers", ev.Evaluate(edgeOnly, @"C:\Users\bin\AppData\Local\Yandex\YandexBrowser\Application\browser.exe", Ctx()).Rule);
        Assert.Equal("allowedBrowsers", ev.Evaluate(edgeOnly, @"C:\Users\bin\AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe", Ctx()).Rule);
    }

    [Fact]
    public void Chromium_portable_named_chrome_exe_is_not_genuine_chrome()
    {
        var facts = new FakeFacts();
        facts.Sig[@"E:\chromium\chrome.exe"] = new SignatureInfo(false, null);
        facts.Sig[@"C:\Users\bin\cent\chrome.exe"] = new SignatureInfo(true, "Cent Studio");
        var ev = new AppRuleEvaluator(facts);
        var p = Policy(browsers: ["chrome.exe", "msedge.exe"]);
        Assert.Equal("allowedBrowsers", ev.Evaluate(p, @"E:\chromium\chrome.exe", Ctx()).Rule);
        Assert.Equal("allowedBrowsers", ev.Evaluate(p, @"C:\Users\bin\cent\chrome.exe", Ctx()).Rule);
    }

    [Fact]
    public void Unrelated_browser_exe_named_browser_exe_is_not_a_browser()
        => Assert.Equal(Verdict.Allow,
            new AppRuleEvaluator(new FakeFacts()).Evaluate(Policy(), @"C:\Program Files\SomeGame\browser.exe", Ctx()).Verdict);

    // ------------------------------------------------------------------ newExecutable

    [Fact]
    public void NewExecutable_applies_only_to_user_writable_paths()
    {
        var ev = new AppRuleEvaluator(new FakeFacts());
        var p = Policy(newExecutable: "block");
        var d = ev.Evaluate(p, @"C:\Users\bin\Downloads\setup.exe", Ctx());
        Assert.Equal(Verdict.Block, d.Verdict);
        Assert.Equal("newExecutable", d.Rule);
        Assert.Equal(Verdict.Allow, ev.Evaluate(p, @"C:\Program Files\App\app.exe", Ctx()).Verdict);
    }

    [Fact]
    public void NewExecutable_allow_lets_user_writable_exes_run()
        => Assert.Equal(Verdict.Allow,
            new AppRuleEvaluator(new FakeFacts()).Evaluate(Policy(newExecutable: "allow"), @"C:\Users\bin\Downloads\x.exe", Ctx()).Verdict);

    [Fact]
    public void Explicit_allow_rule_bypasses_newExecutable()
    {
        var p = Policy(rules: [new AppRule("allow", new AppMatch(Path: @"%LOCALAPPDATA%\Programs\Code\*"))], newExecutable: "block");
        Assert.Equal(Verdict.Allow,
            new AppRuleEvaluator(new FakeFacts()).Evaluate(p, @"C:\Users\bin\AppData\Local\Programs\Code\Code.exe", Ctx()).Verdict);
    }

    [Fact]
    public void NewExecutable_ask_blocks_and_requests_approval_then_honours_store()
    {
        const string path = @"C:\Users\bin\Downloads\game.exe";
        var sha = new string('c', 64);
        var facts = new FakeFacts();
        facts.Sha[path] = sha;
        var ev = new AppRuleEvaluator(facts);
        var p = Policy(newExecutable: "ask");

        var pending = ev.Evaluate(p, path, Ctx());
        Assert.Equal(Verdict.Block, pending.Verdict);
        Assert.True(pending.RequestApproval);
        Assert.Equal(sha, pending.Sha256);
        Assert.Equal("newExecutable:ask", pending.Rule);

        var approved = ev.Evaluate(p, path, Ctx(approval: s => s == sha ? "allow" : null));
        Assert.Equal(Verdict.Allow, approved.Verdict);
        Assert.False(approved.RequestApproval);

        var denied = ev.Evaluate(p, path, Ctx(approval: s => s == sha ? "block" : null));
        Assert.Equal(Verdict.Block, denied.Verdict);
        Assert.False(denied.RequestApproval);
        Assert.Equal("approval", denied.Rule);
    }

    [Fact]
    public void NewExecutable_ask_fails_closed_when_file_unreadable()
    {
        var d = new AppRuleEvaluator(new FakeFacts()).Evaluate(Policy(newExecutable: "ask"), @"C:\Users\bin\Downloads\locked.exe", Ctx());
        Assert.Equal(Verdict.Block, d.Verdict);
        Assert.False(d.RequestApproval);
    }

    [Fact]
    public void Removable_drive_exe_goes_through_newExecutable()
        => Assert.Equal("newExecutable",
            new AppRuleEvaluator(new FakeFacts()).Evaluate(Policy(newExecutable: "block"), @"E:\tools\x.exe", Ctx()).Rule);
}
