using MinControl.Core.Policy;

namespace MinControl.Monitoring.Rules;

public enum Verdict { Allow, Block }

/// <summary>Outcome of evaluating one process image for one managed user.</summary>
/// <param name="Rule">Which rule decided (used as <c>process.blocked.rule</c>): <c>appRules[i]</c>,
/// <c>group:&lt;name&gt;</c>, <c>allowedBrowsers</c>, <c>newExecutable</c>, <c>newExecutable:ask</c>,
/// <c>approval</c>, <c>system</c>, or null for the default allow.</param>
/// <param name="RequestApproval">newExecutable=ask with no stored decision: block now and send
/// <c>request.exe_approval</c> (the caller de-duplicates per sha256).</param>
public sealed record RuleDecision(Verdict Verdict, string? Rule, bool RequestApproval = false, string? Sha256 = null)
{
    public static readonly RuleDecision DefaultAllow = new(Verdict.Allow, null);
    public bool IsBlock => Verdict == Verdict.Block;
}

/// <summary>Per-user, per-instant inputs of the evaluator (everything impure is injected here).</summary>
public sealed class EvaluationContext
{
    public required string Sid { get; init; }
    /// <summary>User profile root, e.g. C:\Users\bin (from IUserDirectory.ProfilePath).</summary>
    public string? ProfilePath { get; init; }
    /// <summary>Groups currently over quota (IScreenTimeEngine.ExhaustedGroups).</summary>
    public IReadOnlyCollection<string> ExhaustedGroups { get; init; } = [];
    /// <summary>Extra roots treated as user-writable: machine %TEMP%, C:\Users\Public, ...</summary>
    public IReadOnlyList<string> ExtraUserWritableRoots { get; init; } = [];
    /// <summary>True when the path is on a removable (or network) drive.</summary>
    public Func<string, bool> IsRemovableOrNetwork { get; init; } = _ => false;
    /// <summary>ACL check (ROUND2 B.1): true when the user or one of its token groups could write, replace or
    /// re-ACL the exe or one of its parent directories. Null = no ACL check (tests, path heuristic only).</summary>
    public Func<string, bool>? IsUserWritableByAcl { get; init; }
    /// <summary>Stored approval for a sha256: "allow" | "block" | null (IApprovalStore.DecisionFor).</summary>
    public Func<string, string?> ApprovalFor { get; init; } = _ => null;
    /// <summary>%windir%, used to protect critical shell processes. Null disables the protection.</summary>
    public string? WindowsDir { get; init; }
    /// <summary>Machine env-var lookup for path globs (tests inject a fake).</summary>
    public Func<string, string?>? MachineVar { get; init; }
}

/// <summary>
/// Pure app-control decision logic (SPEC §5, §8.3). Order:
/// <list type="number">
/// <item>critical Windows shell processes under %windir% are never blocked (a bad rule must not brick the session);</item>
/// <item><c>appRules</c>, first match wins, a rule matches when its <c>match</c> matches and no <c>except</c> entry does;
///   block wins immediately, allow exempts from the browser and newExecutable checks;</item>
/// <item>app group currently exhausted → block (applies even to explicitly allowed apps: quota is time, not trust);</item>
/// <item>a browser that is not a genuine member of <c>web.allowedBrowsers</c> → block;</item>
/// <item>exe under a user-writable location (profile/temp fast path, removable/network, or writable per DACL) → <c>newExecutable</c> (allow | block | ask + IApprovalStore).</item>
/// </list>
/// All AppMatch fields present in one match object must match (AND). sha256/publisher are computed lazily.
/// </summary>
public sealed class AppRuleEvaluator
{
    private static readonly HashSet<string> CriticalShellExes = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer.exe", "sihost.exe", "ctfmon.exe", "dwm.exe", "winlogon.exe", "userinit.exe", "svchost.exe",
        "runtimebroker.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe", "searchhost.exe",
        "searchapp.exe", "textinputhost.exe", "conhost.exe", "taskhostw.exe", "dllhost.exe", "smartscreen.exe",
        "logonui.exe", "fontdrvhost.exe", "lockapp.exe", "applicationframehost.exe", "csrss.exe",
        "securityhealthsystray.exe", "werfault.exe", "consent.exe", "backgroundtaskhost.exe", "rundll32.exe",
        "systemsettings.exe", "shellhost.exe", "widgets.exe", "useroobebroker.exe", "credentialuibroker.exe",
    };

    private readonly IFileFacts _facts;

    public AppRuleEvaluator(IFileFacts facts) => _facts = facts;

    public RuleDecision Evaluate(UserPolicy policy, string exePath, EvaluationContext ctx)
    {
        ArgumentNullException.ThrowIfNull(policy);
        exePath = PathExpander.Normalize(exePath);

        if (IsCriticalShell(exePath, ctx)) return new RuleDecision(Verdict.Allow, "system");

        bool explicitlyAllowed = false;
        for (int i = 0; i < policy.AppRules.Count; i++)
        {
            var rule = policy.AppRules[i];
            if (!Matches(rule.Match, exePath, ctx)) continue;
            if (rule.Except is { Count: > 0 } ex && ex.Any(m => Matches(m, exePath, ctx))) continue;

            if (string.Equals(rule.Action, "block", StringComparison.OrdinalIgnoreCase))
                return new RuleDecision(Verdict.Block, $"appRules[{i}]");
            explicitlyAllowed = true;
            break;
        }

        if (ctx.ExhaustedGroups.Count > 0)
        {
            var group = GroupOf(policy, exePath, ctx);
            if (group is not null && ctx.ExhaustedGroups.Contains(group))
                return new RuleDecision(Verdict.Block, "group:" + group);
        }

        if (explicitlyAllowed) return new RuleDecision(Verdict.Allow, "appRules");

        var kind = KnownBrowsers.Classify(exePath, _facts, out var canonical);
        if (kind != KnownBrowsers.Kind.NotBrowser)
        {
            bool allowed = canonical is not null
                && policy.Web.AllowedBrowsers.Any(b => string.Equals(b, canonical, StringComparison.OrdinalIgnoreCase));
            if (!allowed) return new RuleDecision(Verdict.Block, "allowedBrowsers");
            return RuleDecision.DefaultAllow;
        }

        if (IsUnderUserWritable(exePath, ctx))
            return NewExecutable(policy.NewExecutable, exePath, ctx);

        return RuleDecision.DefaultAllow;
    }

    private RuleDecision NewExecutable(string mode, string exePath, EvaluationContext ctx)
    {
        switch (mode.ToLowerInvariant())
        {
            case "allow":
                return RuleDecision.DefaultAllow;
            case "ask":
                var sha = _facts.Sha256(exePath);
                if (sha is null) return new RuleDecision(Verdict.Block, "newExecutable:ask"); // unreadable: fail closed
                var decision = ctx.ApprovalFor(sha);
                if (string.Equals(decision, "allow", StringComparison.OrdinalIgnoreCase))
                    return new RuleDecision(Verdict.Allow, "approval", Sha256: sha);
                if (string.Equals(decision, "block", StringComparison.OrdinalIgnoreCase))
                    return new RuleDecision(Verdict.Block, "approval", Sha256: sha);
                return new RuleDecision(Verdict.Block, "newExecutable:ask", RequestApproval: true, Sha256: sha);
            default: // "block" and anything unknown: fail closed
                return new RuleDecision(Verdict.Block, "newExecutable");
        }
    }

    /// <summary>First app group (ordinal key order, deterministic) whose match list matches.</summary>
    public string? GroupOf(UserPolicy policy, string exePath, EvaluationContext ctx)
    {
        exePath = PathExpander.Normalize(exePath);
        foreach (var key in policy.AppGroups.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            var g = policy.AppGroups[key];
            foreach (var m in g.Match)
                if (Matches(m, exePath, ctx)) return key;
        }
        return null;
    }

    /// <summary>True when every field present in <paramref name="m"/> matches. An empty match never matches.</summary>
    public bool Matches(AppMatch m, string exePath, EvaluationContext ctx)
    {
        bool any = false;

        // cheap checks first; publisher and sha256 hit the disk (cached)
        if (m.Exe is { } exeGlob)
        {
            any = true;
            if (!Glob.IsMatch(exeGlob, Path.GetFileName(exePath))) return false;
        }
        if (m.Path is { } pathGlob)
        {
            any = true;
            var expanded = PathExpander.Expand(pathGlob, ctx.ProfilePath, ctx.MachineVar);
            if (!Glob.IsMatch(expanded, exePath)) return false;
        }
        if (m.PathUnderUserWritable == true)
        {
            any = true;
            if (!IsUnderUserWritable(exePath, ctx)) return false;
        }
        if (m.Publisher is { } pubGlob)
        {
            any = true;
            var sig = _facts.Signature(exePath);
            if (!sig.Signed || sig.Publisher is null || !Glob.IsMatch(pubGlob, sig.Publisher)) return false;
        }
        if (m.Sha256 is { } sha)
        {
            any = true;
            var actual = _facts.Sha256(exePath);
            if (actual is null || !string.Equals(actual, sha, StringComparison.OrdinalIgnoreCase)) return false;
        }
        return any;
    }

    /// <summary>Exe under the user's profile, a user-writable machine root (%TEMP%, Public...) (fast paths), a
    /// removable/network drive, or anywhere the user's token could write per the real DACLs (SPEC §8.3, ROUND2 B.1).</summary>
    public static bool IsUnderUserWritable(string exePath, EvaluationContext ctx)
    {
        exePath = PathExpander.Normalize(exePath);
        if (ctx.ProfilePath is { Length: > 0 } profile && IsUnder(exePath, profile)) return true;
        foreach (var root in ctx.ExtraUserWritableRoots)
            if (IsUnder(exePath, root)) return true;
        if (exePath.StartsWith(@"\\", StringComparison.Ordinal) && !exePath.StartsWith(@"\\?\", StringComparison.Ordinal))
            return true; // UNC share
        if (ctx.IsRemovableOrNetwork(exePath)) return true;
        return ctx.IsUserWritableByAcl?.Invoke(exePath) ?? false;
    }

    internal static bool IsUnder(string path, string root)
    {
        root = PathExpander.Normalize(root).TrimEnd('\\');
        if (root.Length == 0) return false;
        return path.Length > root.Length
            && path[root.Length] == '\\'
            && path.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A critical shell exe in one of the fixed, admin-only Windows folders: %windir%, System32, SysWOW64,
    /// ImmersiveControlPanel, or a package folder directly under SystemApps. Not "anywhere under %windir%":
    /// %windir%\Tasks, System32\spool\drivers\color, ... are user-writable, and a renamed game dropped there must not
    /// inherit the protection.</summary>
    internal static bool IsCriticalShell(string exePath, EvaluationContext ctx)
    {
        if (ctx.WindowsDir is not { Length: > 0 } win) return false;
        if (!CriticalShellExes.Contains(Path.GetFileName(exePath))) return false;
        var dir = Path.GetDirectoryName(exePath);
        if (dir is null) return false;
        win = PathExpander.Normalize(win).TrimEnd('\\');
        foreach (var fixedDir in (ReadOnlySpan<string>)["", @"\System32", @"\SysWOW64", @"\ImmersiveControlPanel"])
            if (string.Equals(dir, win + fixedDir, StringComparison.OrdinalIgnoreCase)) return true;
        var parent = Path.GetDirectoryName(dir);
        return parent is not null && string.Equals(parent, win + @"\SystemApps", StringComparison.OrdinalIgnoreCase);
    }
}
