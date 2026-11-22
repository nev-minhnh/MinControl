using MinControl.Core.Abstractions;
using MinControl.Core.Cloud;
using Xunit;

namespace MinControl.Core.Tests;

// ROUND2 B.5: users[].foregroundStartedAt (optional, RFC 3339 Z) in DeviceState.
public class DeviceStateTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 23, 9, 0, 0, TimeSpan.Zero);
    private readonly CoreHarness _h = new(Now);

    public DeviceStateTests() => _h.ApplyPolicy(TestData.BasicPolicy());

    public void Dispose() => _h.Dispose();

    private class Foreground : IForegroundTracker
    {
        public (string ExePath, string? Title, bool Idle)? Current(string sid) =>
            sid == TestData.Sid ? (@"C:\Program Files\Game\game.exe", "Game", false) : null;
    }

    private sealed class ForegroundWithSince(DateTimeOffset since) : Foreground, IForegroundSince
    {
        public DateTimeOffset? ForegroundStartedAt(string sid) => sid == TestData.Sid ? since : null;
    }

    private System.Text.Json.Nodes.JsonObject User(IForegroundTracker fg)
    {
        var state = new DeviceStateBuilder(_h.Policy, _h.Engine, _h.Clock, "test", () => fg).Build();
        return state["users"]!.AsArray().Select(u => u!.AsObject()).Single(u => (string?)u["sid"] == TestData.Sid);
    }

    [Fact]
    public void Foreground_started_at_is_reported_when_known()
    {
        var u = User(new ForegroundWithSince(Now.AddMinutes(-7)));
        Assert.Equal("game.exe", (string?)u["foregroundExe"]);
        Assert.Equal("2026-11-23T08:53:00Z", (string?)u["foregroundStartedAt"]);
    }

    [Fact]
    public void Foreground_started_at_is_omitted_when_unknown() =>
        Assert.False(User(new Foreground()).ContainsKey("foregroundStartedAt"));

    [Fact]
    public void Foreground_started_at_never_lies_in_the_future() =>
        Assert.Equal("2026-11-23T09:00:00Z", (string?)User(new ForegroundWithSince(Now.AddMinutes(5)))["foregroundStartedAt"]);
}
