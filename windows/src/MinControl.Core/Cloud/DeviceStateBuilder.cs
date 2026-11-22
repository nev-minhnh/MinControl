using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Policies;
using MinControl.Core.ScreenTime;
using MinControl.Core.Util;

namespace MinControl.Core.Cloud;

/// <summary>
/// Optional seam (win-session may implement and register it): logon/active/workstation-lock status of a user's
/// session. Without it, DeviceState derives loggedOn/active from <see cref="IForegroundTracker"/>.
/// </summary>
public interface IUserSessionStatus
{
    /// <returns>null when the user has no session.</returns>
    (bool Active, bool WorkstationLocked)? Status(string sid);
}

/// <summary>Builds the <c>DeviceState</c> object of API.md §2 from the engine and the foreground tracker.</summary>
public sealed class DeviceStateBuilder
{
    private readonly PolicyProvider _policy;
    private readonly IScreenTimeEngine _engine;
    private readonly IClock _clock;
    private readonly Func<IForegroundTracker?> _foreground;
    private readonly Func<IUserSessionStatus?> _sessions;
    private readonly string _agentVersion;

    public DeviceStateBuilder(PolicyProvider policy, IScreenTimeEngine engine, IClock clock, string agentVersion,
        Func<IForegroundTracker?>? foreground = null, Func<IUserSessionStatus?>? sessions = null)
    {
        _policy = policy; _engine = engine; _clock = clock; _agentVersion = agentVersion;
        _foreground = foreground ?? (() => null);
        _sessions = sessions ?? (() => null);
    }

    public JsonObject Build()
    {
        var now = _clock.UtcNow;
        var p = _policy.Current;
        var users = new JsonArray();
        if (p is not null)
            foreach (var (sid, up) in p.Users)
            {
                var st = _engine.Evaluate(sid, now);
                var fg = _foreground()?.Current(sid);
                var sess = _sessions()?.Status(sid);
                var loggedOn = sess is not null || fg is not null;
                var groups = new JsonObject();
                foreach (var (g, gs) in st.Groups)
                    groups[g] = new JsonObject { ["usedMin"] = gs.UsedMin, ["remainingMin"] = gs.RemainingMin };
                var u = new JsonObject
                {
                    ["sid"] = sid,
                    ["loggedOn"] = loggedOn,
                    ["active"] = sess?.Active ?? (fg is { Idle: false }),
                    ["locked"] = st.Reason == Reasons.Locked,
                    ["lockedUntil"] = st.LockedUntil is { } lu ? Time.Utc(lu) : null,
                    ["remainingMin"] = st.RemainingMin,
                    ["usedMin"] = st.UsedMin,
                    ["groups"] = groups,
                    ["foregroundExe"] = fg is { } f ? Path.GetFileName(f.ExePath) : null,
                    ["foregroundTitle"] = fg is { } f2 && up.Monitoring.ForegroundTitles ? f2.Title : null,
                };
                users.Add(u);
            }
        return new JsonObject
        {
            ["ts"] = Time.Utc(now),
            ["agentVersion"] = _agentVersion,
            ["policyVersion"] = p?.Version,
            ["users"] = users,
        };
    }
}
