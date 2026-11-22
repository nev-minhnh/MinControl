using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.ScreenTime;
using MinControl.Core.Storage;
using Xunit;

namespace MinControl.Core.Tests;

/// <summary>Policy = protocol/fixtures/policy/valid/basic.json: Asia/Ho_Chi_Minh (UTC+7, no DST), Mon–Fri 15:00–21:00 and
/// 120 min, Sat–Sun 08:00–21:30 and 180 min, group "games" (Minecraft*.exe) 60 min on weekdays. 2026-11-23 is a Monday.</summary>
public class ScreenTimeTests : IDisposable
{
    private static readonly TimeSpan Vn = TimeSpan.FromHours(7);
    private static DateTimeOffset L(int day, int h, int m = 0) => new DateTimeOffset(2026, 11, day, h, m, 0, Vn).ToUniversalTime();
    private const string Sid = TestData.Sid;
    private const string Game = @"C:\Games\Minecraft.exe";
    private const string Editor = @"C:\Windows\notepad.exe";

    private readonly CoreHarness _h = new(L(23, 16));

    public ScreenTimeTests() => _h.ApplyPolicy(TestData.BasicPolicy());

    public void Dispose() => _h.Dispose();

    private void Use(int minutes, string? exe = Editor)
    {
        for (int i = 0; i < minutes; i++) _h.Engine.RecordUsage(Sid, exe, 60_000);
    }

    private ScreenTimeState Now() => _h.Engine.Evaluate(Sid, _h.Clock.UtcNow);

    private async Task Cmd(string type, Action<JsonObject>? more = null)
    {
        var body = new JsonObject { ["type"] = type, ["userSid"] = Sid };
        more?.Invoke(body);
        var ack = await _h.CommandAsync(body);
        Assert.Equal("applied", ack.Status);
    }

    [Fact]
    public void Fresh_day_inside_window_has_full_quota()
    {
        var s = Now();
        Assert.True(s.Allowed);
        Assert.Equal(Reasons.Ok, s.Reason);
        Assert.Equal(0, s.UsedMin);
        Assert.Equal(120, s.RemainingMin);
    }

    [Fact]
    public void Usage_reduces_remaining_quota()
    {
        Use(100);
        var s = Now();
        Assert.Equal(100, s.UsedMin);
        Assert.Equal(20, s.RemainingMin);
        Assert.Equal(_h.Clock.UtcNow.AddMinutes(20), s.NextChangeUtc);
    }

    [Fact]
    public void Quota_exhausted_blocks_until_next_day()
    {
        Use(120);
        var s = Now();
        Assert.False(s.Allowed);
        Assert.Equal(Reasons.QuotaExhausted, s.Reason);
        Assert.Equal(0, s.RemainingMin);
        Assert.Equal(L(24, 0), s.NextChangeUtc);
    }

    [Fact]
    public void Single_delta_is_capped()
    {
        _h.Engine.RecordUsage(Sid, Editor, 10 * 60_000);
        Assert.Equal(2, Now().UsedMin);
    }

    [Fact]
    public void Outside_window_is_not_allowed_and_points_to_next_window()
    {
        _h.Clock.UtcNow = L(23, 22);
        var s = Now();
        Assert.False(s.Allowed);
        Assert.Equal(Reasons.OutsideWindow, s.Reason);
        Assert.Equal(L(24, 15), s.NextChangeUtc);
        _h.Clock.UtcNow = L(23, 9);
        Assert.Equal(L(23, 15), Now().NextChangeUtc);
    }

    [Fact]
    public void Window_end_caps_remaining_minutes()
    {
        _h.Clock.UtcNow = L(23, 20, 30);
        var s = Now();
        Assert.Equal(30, s.RemainingMin);
        Assert.Equal(L(23, 21), s.NextChangeUtc);
    }

    [Fact]
    public void Window_boundaries_are_start_inclusive_end_exclusive()
    {
        _h.Clock.UtcNow = L(23, 15);
        Assert.True(Now().Allowed);
        _h.Clock.UtcNow = L(23, 21);
        Assert.Equal(Reasons.OutsideWindow, Now().Reason);
    }

    [Fact]
    public void Midnight_rollover_resets_usage_in_policy_timezone()
    {
        var p = TestData.BasicPolicy();
        var st = TestData.User(p)["screenTime"]!;
        st["allowedWindows"]!["mon"] = new JsonArray("00:00-24:00");
        st["allowedWindows"]!["tue"] = new JsonArray("00:00-24:00");
        _h.ApplyPolicy(p);

        _h.Clock.UtcNow = L(23, 23, 0);
        Use(50);                                   // 23:00–23:50 local Monday
        Assert.Equal(50, Now().UsedMin);
        // a window ending 24:00 continues into Tuesday's 00:00 window: no premature "10 minutes left"
        Assert.Equal(70, Now().RemainingMin);

        _h.Clock.UtcNow = L(24, 0, 5);             // Tuesday 00:05 local (still Monday 17:05 UTC)
        Use(1);
        var s = Now();
        Assert.Equal(1, s.UsedMin);
        Assert.Equal(119, s.RemainingMin);
        Assert.Equal(50, _h.Engine.Evaluate(Sid, L(23, 23, 59)).UsedMin);   // Monday's ledger untouched
    }

    [Fact]
    public async Task Add_time_extends_todays_quota()
    {
        Use(120);
        Assert.Equal(Reasons.QuotaExhausted, Now().Reason);
        await Cmd("add_time", b => b["minutes"] = 30);
        var s = Now();
        Assert.True(s.Allowed);
        Assert.Equal(30, s.RemainingMin);
    }

    [Fact]
    public async Task Negative_add_time_reduces_quota()
    {
        await Cmd("add_time", b => b["minutes"] = -30);
        Assert.Equal(90, Now().RemainingMin);
    }

    [Fact]
    public async Task Add_time_applies_only_to_the_local_day_it_was_given()
    {
        await Cmd("add_time", b => b["minutes"] = 30);
        _h.Clock.UtcNow = L(24, 16);
        Assert.Equal(120, Now().RemainingMin);
    }

    [Fact]
    public async Task Pause_suspends_windows_and_quota_until_expiry()
    {
        _h.Clock.UtcNow = L(23, 22);
        await Cmd("pause_limits", b => b["until"] = MinControl.Core.Util.Time.Utc(L(23, 23)));
        var s = Now();
        Assert.True(s.Allowed);
        Assert.Null(s.RemainingMin);
        Assert.Equal(L(23, 23), s.NextChangeUtc);
        _h.Clock.UtcNow = L(23, 23);
        Assert.Equal(Reasons.OutsideWindow, Now().Reason);
    }

    [Fact]
    public async Task Lock_until_blocks_then_expires()
    {
        await Cmd("lock_now", b => b["until"] = MinControl.Core.Util.Time.Utc(L(23, 17)));
        var s = Now();
        Assert.False(s.Allowed);
        Assert.Equal(Reasons.Locked, s.Reason);
        Assert.Equal(L(23, 17), s.LockedUntil);
        Assert.Contains($"lock {Sid} 60", _h.Session.Calls);
        _h.Clock.UtcNow = L(23, 17);
        Assert.Equal(Reasons.Ok, Now().Reason);
    }

    [Fact]
    public async Task Lock_without_until_lasts_until_unlock()
    {
        await Cmd("lock_now");
        _h.Clock.UtcNow = L(25, 16);
        Assert.Equal(Reasons.Locked, Now().Reason);
        Assert.Null(Now().LockedUntil);
        await Cmd("unlock");
        Assert.Equal(Reasons.Ok, Now().Reason);
    }

    [Fact]
    public async Task Lock_beats_quota_and_newest_of_lock_or_pause_wins()
    {
        await Cmd("pause_limits", b => b["until"] = MinControl.Core.Util.Time.Utc(L(23, 20)));
        await Cmd("lock_now");
        Assert.Equal(Reasons.Locked, Now().Reason);
        await Cmd("pause_limits", b => b["until"] = MinControl.Core.Util.Time.Utc(L(23, 20)));
        Assert.True(Now().Allowed);
    }

    [Fact]
    public void Group_quota_is_tracked_and_exhausted()
    {
        Use(59, Game);
        Assert.Empty(_h.Engine.ExhaustedGroups(Sid, _h.Clock.UtcNow));
        Assert.Equal(1, Now().Groups["games"].RemainingMin);
        Use(1, Game);
        Use(10, Editor);
        var s = Now();
        Assert.Equal(60, s.Groups["games"].UsedMin);
        Assert.Equal(0, s.Groups["games"].RemainingMin);
        Assert.Equal(70, s.UsedMin);
        Assert.True(s.Allowed);                     // total quota still left
        Assert.Equal(["games"], _h.Engine.ExhaustedGroups(Sid, _h.Clock.UtcNow));
    }

    [Fact]
    public async Task Group_add_time_and_pause_lift_group_exhaustion()
    {
        Use(60, Game);
        await Cmd("add_time", b => { b["minutes"] = 15; b["group"] = "games"; });
        Assert.Empty(_h.Engine.ExhaustedGroups(Sid, _h.Clock.UtcNow));
        Assert.Equal(15, Now().Groups["games"].RemainingMin);
        Use(15, Game);
        Assert.Equal(["games"], _h.Engine.ExhaustedGroups(Sid, _h.Clock.UtcNow));
        await Cmd("pause_limits", b => b["until"] = MinControl.Core.Util.Time.Utc(L(23, 20)));
        Assert.Empty(_h.Engine.ExhaustedGroups(Sid, _h.Clock.UtcNow));
    }

    [Fact]
    public void Group_membership_uses_exe_glob() =>
        Assert.Equal("games", _h.Engine.GroupOf(Sid, @"D:\x\MinecraftLauncher.exe"));

    [Fact]
    public void Unmanaged_user_is_not_managed()
    {
        var s = _h.Engine.Evaluate("S-1-5-21-1-2-3-4242", _h.Clock.UtcNow);
        Assert.True(s.Allowed);
        Assert.Equal(Reasons.NotManaged, s.Reason);
    }

    [Fact]
    public void Ledger_survives_flush_and_new_engine()
    {
        Use(30);
        _h.Engine.Flush();
        using var again = new ScreenTimeEngine(_h.Store, _h.Policy, _h.Clock);
        Assert.Equal(30, again.Evaluate(Sid, _h.Clock.UtcNow).UsedMin);
    }

    [Fact]
    public void Empty_window_list_means_no_screen_time_that_day()
    {
        var p = TestData.BasicPolicy();
        TestData.User(p)["screenTime"]!["allowedWindows"]!["mon"] = new JsonArray();
        _h.ApplyPolicy(p);
        Assert.Equal(Reasons.OutsideWindow, Now().Reason);
    }

    [Fact]
    public void Calculator_is_pure()
    {
        var policy = _h.Policy.ForUser(Sid)!;
        var tz = _h.Policy.TimeZone;
        var ledger = new Dictionary<string, long> { [""] = 45 * 60_000L, ["games"] = 10 * 60_000L };
        var a = ScreenTimeCalculator.Evaluate(policy, tz, UserOverrides.None, ledger, L(23, 16));
        var b = ScreenTimeCalculator.Evaluate(policy, tz, UserOverrides.None, ledger, L(23, 16));
        Assert.Equal(a.RemainingMin, b.RemainingMin);
        Assert.Equal(75, a.RemainingMin);
        Assert.Equal(50, a.Groups["games"].RemainingMin);
    }

    [Fact]
    public async Task Expired_overrides_are_pruned()
    {
        await Cmd("lock_now", b => b["until"] = MinControl.Core.Util.Time.Utc(L(23, 17)));
        _h.Clock.UtcNow = L(24, 16);
        _h.Engine.Flush();
        Assert.DoesNotContain(_h.Store.GetOverrides(Sid), o => o.Kind == OverrideKinds.Lock);
    }
}
