
namespace MinControl.Core.Policy;

// C# mirror of protocol/policy.schema.json. Owned by the lead; extend only via a protocol change.
// Serialise with MinControl.Core.Protocol.ProtocolJson.Options (camelCase).

public sealed record WeekdayMap<T>(T Mon, T Tue, T Wed, T Thu, T Fri, T Sat, T Sun)
{
    public T For(DayOfWeek day) => day switch
    {
        DayOfWeek.Monday => Mon, DayOfWeek.Tuesday => Tue, DayOfWeek.Wednesday => Wed,
        DayOfWeek.Thursday => Thu, DayOfWeek.Friday => Fri, DayOfWeek.Saturday => Sat,
        _ => Sun,
    };
}

public sealed record DevicePolicy(
    int Version,
    string Timezone,
    IReadOnlyDictionary<string, UserPolicy> Users,   // key = SID of a managed user
    RetentionDays RetentionDays);

public sealed record RetentionDays(int Events, int Web, int Screenshots);

public sealed record UserPolicy(
    string Label,
    ScreenTimePolicy ScreenTime,
    IReadOnlyDictionary<string, AppGroup> AppGroups,
    IReadOnlyList<AppRule> AppRules,
    string NewExecutable,            // allow | block | ask
    WebPolicy Web,
    MonitoringPolicy Monitoring,
    string? AppMode = null,          // blocklist (default) | allowlist (API.md §17)
    KeywordPolicy? Keywords = null)
{
    /// <summary>True when only allowed apps may run (<c>appMode: "allowlist"</c>).</summary>
    public bool IsAppAllowlist => string.Equals(AppMode, "allowlist", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Banned words (API.md §17): matched case- and diacritics-insensitively on word boundaries.</summary>
public sealed record KeywordPolicy(IReadOnlyList<string> Words, bool MatchSearches, bool MatchTitles);

public sealed record ScreenTimePolicy(
    WeekdayMap<int> DailyQuotaMin,
    WeekdayMap<IReadOnlyList<string>> AllowedWindows,   // "HH:MM-HH:MM" in policy timezone
    IReadOnlyList<int> WarnAtMin,
    int GraceSec,
    bool CountIdle,
    int IdleThresholdSec);

public sealed record AppGroup(string Label, IReadOnlyList<AppMatch> Match, WeekdayMap<int>? DailyQuotaMin = null);

public sealed record AppRule(string Action, AppMatch Match, IReadOnlyList<AppMatch>? Except = null); // block | allow

public sealed record AppMatch(
    string? Exe = null,
    string? Path = null,
    string? Publisher = null,
    string? Sha256 = null,
    bool? PathUnderUserWritable = null);

public sealed record WebPolicy(
    string Mode,                                   // blocklist | allowlist
    IReadOnlyList<string> BlockedCategories,
    IReadOnlyList<string> BlockDomains,
    IReadOnlyList<string> AllowDomains,
    bool SafeSearch,
    string Youtube,                                // off | moderate | strict
    IReadOnlyList<string> AllowedBrowsers,         // msedge.exe | chrome.exe
    IReadOnlyList<AppMatch> NetExemptApps,
    IReadOnlyDictionary<string, WeekdayMap<IReadOnlyList<string>>>? CategorySchedules = null,
    IReadOnlyList<string>? BlockedServices = null,  // service ids from protocol/services.json
    IReadOnlyList<string>? AllowedServices = null);

public sealed record MonitoringPolicy(
    bool ForegroundTitles,
    bool BrowserHistory,
    bool DomainLog,
    bool Downloads,
    bool Usb,
    ScreenshotPolicy Screenshots);

public sealed record ScreenshotPolicy(int IntervalMin, bool OnlyWhenActive, int MaxWidth, int JpegQuality);
