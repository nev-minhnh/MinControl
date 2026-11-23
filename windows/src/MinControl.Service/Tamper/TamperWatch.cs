using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Events;
using MinControl.Core.Policies;
using MinControl.Service.Logic;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MinControl.Service.Tamper;

/// <summary>Clock-jump (wall vs monotonic &gt; 2 min) and system-timezone change detection (spec 8.8, I6), and
/// <c>tamper.state_tampered</c> once at start when the policy stored in state.db failed re-verification.
/// Device-level events: userSid is null.</summary>
internal sealed class TamperWatch(IEventSink events, IClock clock, PolicyProvider policy, ILogger<TamperWatch> log) : BackgroundService
{
    private static readonly TimeSpan Period = TimeSpan.FromSeconds(5);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (policy.StoredPolicyRejected)
        {
            log.LogWarning("stored policy failed re-verification at startup; reporting tamper.state_tampered");
            events.Emit(EventTypes.TamperStateTampered, null, new JsonObject
            {
                ["detail"] = TamperText.StateTampered,
            });
        }

        // Environment.TickCount64 keeps counting across sleep/hibernate, so resume does not look like a jump.
        var jumps = new ClockJumpDetector();
        jumps.Check(clock.UtcNow.ToUnixTimeMilliseconds(), Environment.TickCount64);
        var tz = CurrentTimeZone();
        using var timer = new PeriodicTimer(Period);
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            try
            {
                if (jumps.Check(clock.UtcNow.ToUnixTimeMilliseconds(), Environment.TickCount64) is long jumpSec)
                {
                    log.LogWarning("system clock jumped {Sec}s", jumpSec);
                    events.Emit(EventTypes.TamperClockJump, null, new JsonObject { ["jumpSec"] = jumpSec, ["detail"] = TamperText.ClockJump(jumpSec) });
                }
                var nowTz = CurrentTimeZone();
                if (nowTz != tz)
                {
                    log.LogWarning("system timezone changed {Old} -> {New}", tz, nowTz);
                    events.Emit(EventTypes.TamperTimezoneChanged, null, new JsonObject { ["detail"] = TamperText.TimezoneChanged(tz, nowTz) });
                    tz = nowTz;
                }
            }
            catch (Exception e) { log.LogError(e, "tamper watch tick failed"); }
        }
    }

    private static string CurrentTimeZone()
    {
        TimeZoneInfo.ClearCachedData();
        var local = TimeZoneInfo.Local;
        return $"{local.Id} ({local.BaseUtcOffset})";
    }
}
