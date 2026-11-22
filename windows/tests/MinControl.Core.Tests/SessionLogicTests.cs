#if SESSION_LOGIC_LINKED
// Tests for the pure win-session logic (MinControl.Service/Logic/*.cs). Those files are platform-neutral and
// are compiled into this net10.0 test project by link - see docs/contract-requests/session.md (needs the
// csproj snippet that also defines SESSION_LOGIC_LINKED; until then this file compiles to nothing).
using System.Buffers.Binary;
using System.Text;
using System.Text.Json.Nodes;
using MinControl.Service.Logic;
using Xunit;

namespace MinControl.Core.Tests;

public class IpcFramingTests
{
    private static IpcMessage RoundTrip(IpcMessage m)
    {
        using var ms = new MemoryStream(IpcFraming.Encode(m));
        return IpcFraming.ReadAsync(ms, CancellationToken.None).GetAwaiter().GetResult()!;
    }

    [Fact]
    public void RoundTripsTypeAndData_IncludingVietnamese()
    {
        var back = RoundTrip(IpcMessage.Of(IpcTypes.Message, new JsonObject { ["text"] = "Đi ngủ thôi con 😴", ["n"] = 5 }));
        Assert.Equal(IpcTypes.Message, back.Type);
        Assert.Equal("Đi ngủ thôi con 😴", back.Str("text"));
        Assert.Equal(5L, back.Long("n"));
    }

    [Fact]
    public void LengthPrefixIsLittleEndianPayloadLength()
    {
        var frame = IpcFraming.Encode(IpcMessage.Of(IpcTypes.Heartbeat));
        Assert.Equal((uint)(frame.Length - 4), BinaryPrimitives.ReadUInt32LittleEndian(frame));
        Assert.Equal("{\"type\":\"heartbeat\",\"data\":{}}", Encoding.UTF8.GetString(frame, 4, frame.Length - 4));
    }

    [Fact]
    public async Task ReadsConsecutiveFramesThenNullAtCleanEof()
    {
        var ms = new MemoryStream();
        await IpcFraming.WriteAsync(ms, IpcMessage.Of(IpcTypes.Idle, new JsonObject { ["idleMs"] = 1234 }), default);
        await IpcFraming.WriteAsync(ms, IpcMessage.Of(IpcTypes.Foreground, new JsonObject { ["exe"] = @"C:\a\b.exe" }), default);
        ms.Position = 0;
        Assert.Equal(1234L, (await IpcFraming.ReadAsync(ms, default))!.Long("idleMs"));
        Assert.Equal(@"C:\a\b.exe", (await IpcFraming.ReadAsync(ms, default))!.Str("exe"));
        Assert.Null(await IpcFraming.ReadAsync(ms, default));
    }

    [Fact]
    public async Task ReassemblesFramesFromOneByteReads()
    {
        var frame = IpcFraming.Encode(IpcMessage.Of(IpcTypes.Warning, new JsonObject { ["remainingMin"] = 5 }));
        var back = await IpcFraming.ReadAsync(new TrickleStream(frame), default);
        Assert.Equal(5L, back!.Long("remainingMin"));
    }

    [Fact]
    public async Task MissingDataBecomesEmptyObject()
    {
        var payload = Encoding.UTF8.GetBytes("{\"type\":\"clear_overlay\"}");
        var back = await IpcFraming.ReadAsync(new MemoryStream(Frame(payload)), default);
        Assert.Equal(IpcTypes.ClearOverlay, back!.Type);
        Assert.Empty(back.Data);
    }

    [Theory]
    [InlineData(new byte[] { 1, 0 })]                          // truncated header
    [InlineData(new byte[] { 10, 0, 0, 0, (byte)'{' })]        // truncated payload
    [InlineData(new byte[] { 0, 0, 0, 0 })]                    // zero length
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0x7F })]        // oversize
    public async Task RejectsMalformedFrames(byte[] bytes) =>
        await Assert.ThrowsAsync<InvalidDataException>(() => IpcFraming.ReadAsync(new MemoryStream(bytes), default));

    [Theory]
    [InlineData("not json")]
    [InlineData("[1,2]")]
    [InlineData("{\"data\":{}}")]
    [InlineData("{\"type\":\"\"}")]
    [InlineData("{\"type\":\"x\",\"data\":5}")]
    public async Task RejectsBadPayloads(string json) =>
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            IpcFraming.ReadAsync(new MemoryStream(Frame(Encoding.UTF8.GetBytes(json))), default));

    [Fact]
    public void EncodeRejectsOversizePayload()
    {
        var big = new string('a', IpcFraming.MaxFrameBytes);
        Assert.Throws<InvalidDataException>(() => IpcFraming.Encode(IpcMessage.Of(IpcTypes.CaptureResult, new JsonObject { ["jpeg"] = big })));
    }

    [Fact]
    public void PipeNameIsPerSession() => Assert.Equal("MinControl.Session.3", IpcFraming.PipeName(3));

    private static byte[] Frame(byte[] payload)
    {
        var f = new byte[payload.Length + 4];
        BinaryPrimitives.WriteUInt32LittleEndian(f, (uint)payload.Length);
        payload.CopyTo(f, 4);
        return f;
    }

    private sealed class TrickleStream(byte[] data) : MemoryStream(data)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) =>
            base.ReadAsync(buffer[..Math.Min(1, buffer.Length)], ct);
    }
}

public class WarningSchedulerTests
{
    private static readonly int[] Warn = [5, 1];

    [Fact]
    public void FiresEachThresholdOnce()
    {
        var s = new WarningScheduler();
        Assert.Null(s.Update(Warn, 10));
        Assert.Equal(5, s.Update(Warn, 5));
        Assert.Null(s.Update(Warn, 5));
        Assert.Null(s.Update(Warn, 3));
        Assert.Equal(1, s.Update(Warn, 1));
        Assert.Null(s.Update(Warn, 1));
        Assert.Null(s.Update(Warn, 0)); // exhaustion overlay handles 0
    }

    [Fact]
    public void JumpPastSeveralThresholdsFiresOnceWithActualRemaining()
    {
        var s = new WarningScheduler();
        Assert.Equal(1, s.Update(Warn, 1)); // e.g. logon with 1 min left
        Assert.Null(s.Update(Warn, 1));
    }

    [Fact]
    public void ReArmsWhenTimeIsAdded()
    {
        var s = new WarningScheduler();
        Assert.Equal(5, s.Update(Warn, 5));
        Assert.Null(s.Update(Warn, 35));   // add_time +30
        Assert.Equal(5, s.Update(Warn, 5));
    }

    [Fact]
    public void UnlimitedClearsState()
    {
        var s = new WarningScheduler();
        Assert.Equal(4, s.Update(Warn, 4));
        Assert.Null(s.Update(Warn, null)); // pause_limits
        Assert.Equal(4, s.Update(Warn, 4));
    }

    [Fact]
    public void IgnoresNonPositiveThresholds() => Assert.Null(new WarningScheduler().Update([0, -1], 0));
}

public class LockoutTrackerTests
{
    private const long Logon = 0;

    [Fact]
    public void MidSessionUsesGraceThenLogsOffAndRetries()
    {
        var t = new LockoutTracker();
        var now = 3_600_000L;
        Assert.Equal(new LockoutAction(LockoutKind.ShowOverlay, "quota_exhausted", 60), t.Update(false, "quota_exhausted", 60, now, Logon));
        Assert.Equal(LockoutKind.None, t.Update(false, "quota_exhausted", 60, now + 59_000, Logon).Kind);
        Assert.Equal(LockoutKind.Logoff, t.Update(false, "quota_exhausted", 60, now + 60_000, Logon).Kind);
        Assert.Equal(LockoutKind.None, t.Update(false, "quota_exhausted", 60, now + 61_000, Logon).Kind);
        Assert.Equal(LockoutKind.Logoff, t.Update(false, "quota_exhausted", 60, now + 90_000, Logon).Kind);
    }

    [Fact]
    public void LogonWhileNotAllowedGets30Seconds()
    {
        var t = new LockoutTracker();
        var a = t.Update(false, "outside_window", 300, 5_000, Logon);
        Assert.Equal(LockoutKind.ShowOverlay, a.Kind);
        Assert.Equal(LockoutTracker.LogonNotAllowedGraceSec, a.SecondsLeft);
        Assert.Equal(LockoutKind.Logoff, t.Update(false, "outside_window", 300, 35_000, Logon).Kind);
    }

    [Fact]
    public void AllowedAgainClearsOverlay()
    {
        var t = new LockoutTracker();
        t.Update(false, "quota_exhausted", 60, 100_000, Logon);
        Assert.True(t.Active);
        Assert.Equal(LockoutKind.ClearOverlay, t.Update(true, "ok", 60, 110_000, Logon).Kind);
        Assert.False(t.Active);
        Assert.Equal(LockoutKind.None, t.Update(true, "ok", 60, 111_000, Logon).Kind);
    }

    [Fact]
    public void ReasonChangeRefreshesOverlayButKeepsDeadline()
    {
        var t = new LockoutTracker();
        t.Update(false, "quota_exhausted", 60, 100_000, Logon);
        var a = t.Update(false, "locked", 60, 130_000, Logon);
        Assert.Equal(new LockoutAction(LockoutKind.ShowOverlay, "locked", 30), a);
        Assert.Equal(LockoutKind.Logoff, t.Update(false, "locked", 60, 160_000, Logon).Kind);
    }

    [Fact]
    public void ZeroGraceLogsOffOnNextTick()
    {
        var t = new LockoutTracker();
        Assert.Equal(0, t.Update(false, "locked", 0, 100_000, Logon).SecondsLeft);
        Assert.Equal(LockoutKind.Logoff, t.Update(false, "locked", 0, 101_000, Logon).Kind);
    }
}

public class UsageAggregatorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 22, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public void FlushesPerExeOnMinuteRollover()
    {
        var a = new UsageAggregator();
        for (var i = 0; i < 40; i++) Assert.Empty(a.Add(T0.AddSeconds(i), "game.exe", "Level 1", 1000));
        for (var i = 40; i < 60; i++) Assert.Empty(a.Add(T0.AddSeconds(i), "msedge.exe", null, 1000));
        var ticks = a.Add(T0.AddSeconds(60), "msedge.exe", null, 1000);
        Assert.Equal(2, ticks.Count);
        var game = ticks.Single(t => t.Exe == "game.exe");
        Assert.Equal(T0, game.MinuteStart);
        Assert.Equal(40, game.ActiveSec);
        Assert.Equal("Level 1", game.Title);
        Assert.Equal(20, ticks.Single(t => t.Exe == "msedge.exe").ActiveSec);
    }

    [Fact]
    public void ClampsToSixtySecondsAndDropsEmpty()
    {
        var a = new UsageAggregator();
        a.Add(T0, "a.exe", null, 90_000);
        a.Add(T0.AddSeconds(1), "b.exe", null, 0);
        var ticks = a.Add(T0.AddMinutes(1), "", null, 0);
        Assert.Equal(60, Assert.Single(ticks).ActiveSec);
        Assert.Empty(a.Flush());
    }

    [Fact]
    public void MinuteOfTruncatesToUtcMinute() =>
        Assert.Equal(T0, UsageAggregator.MinuteOf(new DateTimeOffset(2026, 11, 22, 15, 0, 59, TimeSpan.FromHours(7))));
}

public class ClockJumpDetectorTests
{
    [Fact]
    public void ReportsJumpsBeyondTwoMinutesBothWays()
    {
        var d = new ClockJumpDetector();
        Assert.Null(d.Check(1_000_000, 0));
        Assert.Null(d.Check(1_005_000, 5_000));            // normal
        Assert.Null(d.Check(1_010_000 + 60_000, 10_000));  // +60 s NTP step: tolerated
        Assert.Equal(3600, d.Check(1_075_000 + 3_600_000, 15_000)); // +1 h
        Assert.Equal(-7200, d.Check(1_080_000 + 3_600_000 - 7_200_000, 20_000)); // -2 h
    }

    [Fact]
    public void SlowDriftNeverAccumulates()
    {
        var d = new ClockJumpDetector();
        long wall = 0;
        for (var i = 0; i < 1000; i++, wall += 5_000 + 1_000) // 1 s drift per 5 s tick
            Assert.Null(d.Check(wall, i * 5_000L));
    }
}

public class DailyLatchTests
{
    [Fact]
    public void FiresOncePerKeyPerDay()
    {
        var l = new DailyLatch();
        var d = new DateOnly(2026, 11, 22);
        Assert.True(l.TryFire("S-1-5-21-1", d));
        Assert.False(l.TryFire("s-1-5-21-1", d));
        Assert.True(l.TryFire("S-1-5-21-2", d));
        Assert.True(l.TryFire("S-1-5-21-1", d.AddDays(1)));
    }
}
#endif
