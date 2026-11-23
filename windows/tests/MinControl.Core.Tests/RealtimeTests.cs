using System.Net;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Cloud;
using MinControl.Core.Storage;
using MinControl.NetGuard;
using MinControl.NetGuard.Telemetry;
using Xunit;

namespace MinControl.Core.Tests;

/// <summary>API.md section 15: live event push, in-flight bookkeeping, state debounce, net.domain first-seen.</summary>
public class RealtimeTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 23, 5, 0, 0, TimeSpan.Zero);

    private sealed class Frames
    {
        public List<string> List { get; } = [];
        public Task Send(string s) { lock (List) List.Add(s); return Task.CompletedTask; }
        public int EventCount { get { lock (List) return List.Sum(f => JsonNode.Parse(f)!["events"]!.AsArray().Count); } }
    }

    private static (StateStore Store, FakeClock Clock, LiveEventPusher Pusher, Frames Frames) Fixture(TimeSpan? delay = null)
    {
        var store = new StateStore(":memory:");
        var clock = new FakeClock(T0);
        var pusher = new LiveEventPusher(store, new InFlightEvents(clock)) { Delay = delay ?? TimeSpan.FromHours(1) };
        var frames = new Frames();
        pusher.Attach(frames.Send);
        return (store, clock, pusher, frames);
    }

    private static string Ev(string id, int pad = 0) => "{\"id\":\"" + id + "\",\"type\":\"usage.tick\",\"pad\":\"" + new string('x', pad) + "\"}";

    private static long Add(StateStore s, LiveEventPusher p, string id, int pad = 0)
    {
        var json = Ev(id, pad);
        var row = s.EnqueueOutbox("usage.tick", json);
        p.Enqueue(row, id, json);
        return row;
    }

    private static async Task WaitFor(Func<bool> cond)
    {
        for (int i = 0; i < 200 && !cond(); i++) await Task.Delay(10);
        Assert.True(cond());
    }

    [Fact]
    public async Task Coalesces_events_within_window_into_one_frame()
    {
        var (store, _, pusher, frames) = Fixture(TimeSpan.FromMilliseconds(80));
        using var _s = store;
        for (int i = 0; i < 3; i++) Add(store, pusher, "E" + i);
        Assert.Empty(frames.List);
        await WaitFor(() => frames.EventCount == 3);
        Assert.Single(frames.List);
        Assert.StartsWith("{\"t\":\"events\",\"events\":[", frames.List[0]);
    }

    [Fact]
    public async Task Frames_are_capped_at_50_events_and_64kb()
    {
        var (store, _, pusher, frames) = Fixture();
        using var _s = store;
        for (int i = 0; i < 120; i++) Add(store, pusher, "A" + i);
        await pusher.FlushAsync();
        await WaitFor(() => frames.EventCount == 120);
        lock (frames.List) Assert.All(frames.List, f => Assert.True(JsonNode.Parse(f)!["events"]!.AsArray().Count <= 50));

        var (store2, _, p2, f2) = Fixture();
        using var _s2 = store2;
        for (int i = 0; i < 10; i++) Add(store2, p2, "B" + i, pad: 20_000);
        await p2.FlushAsync();
        await WaitFor(() => f2.EventCount == 10);
        lock (f2.List)
        {
            Assert.True(f2.List.Count >= 4);
            Assert.All(f2.List, f => Assert.True(System.Text.Encoding.UTF8.GetByteCount(f) <= LiveEventPusher.MaxFrameBytes));
        }
    }

    [Fact]
    public async Task Ack_deletes_acked_and_rejected_rows_and_keeps_unacked()
    {
        var (store, _, pusher, _) = Fixture();
        using var _s = store;
        Add(store, pusher, "E1"); Add(store, pusher, "E2"); var r3 = Add(store, pusher, "E3");
        await pusher.FlushAsync();
        var n = pusher.HandleAck(new JsonObject { ["t"] = "events_ack", ["ids"] = new JsonArray("E1"), ["rejected"] = new JsonArray("E2") });
        Assert.Equal(2, n);
        Assert.Equal([r3], store.PeekOutbox(10).Select(x => x.Id).ToArray());
        Assert.Equal(0, pusher.HandleAck(new JsonObject { ["ids"] = new JsonArray("E1", "nope") })); // unknown / repeated ids are ignored
    }

    [Fact]
    public async Task In_flight_rows_are_skipped_by_http_batch_until_30s_timeout()
    {
        var (store, clock, pusher, _) = Fixture();
        using var _s = store;
        var rIn = Add(store, pusher, "E1");
        await pusher.FlushAsync();                                // E1 now in flight
        store.EnqueueOutbox("usage.tick", Ev("E2"));              // never pushed (queued while the WS was down)

        Assert.True(pusher.InFlight.IsInFlight(rIn));
        var token = new UploadTokenHolder();
        token.Set("tok", clock.UtcNow.AddHours(1));
        var handler = new RecordingHandler();
        var up = new CloudUploader(new HttpClient(handler), store, token, clock, () => "http://example.test") { InFlight = pusher.InFlight };
        store.SetMeta(StateStore.MetaKeys.DeviceId, "dev1");

        Assert.Equal(UploadResult.Done, await up.FlushEventsAsync(CancellationToken.None));
        Assert.Single(handler.Bodies);
        Assert.Contains("E2", handler.Bodies[0]);
        Assert.DoesNotContain("E1", handler.Bodies[0]);
        Assert.Equal([rIn], store.PeekOutbox(10).Select(x => x.Id).ToArray());

        clock.Advance(TimeSpan.FromSeconds(31));                  // no ack for 30 s: HTTP sends it
        Assert.False(pusher.InFlight.IsInFlight(rIn));
        token.Set("tok", clock.UtcNow.AddHours(1));
        Assert.Equal(UploadResult.Done, await up.FlushEventsAsync(CancellationToken.None));
        Assert.Contains("E1", handler.Bodies[1]);
        Assert.Empty(store.PeekOutbox(10));
    }

    [Fact]
    public async Task Nothing_is_sent_when_detached()
    {
        var (store, _, pusher, frames) = Fixture(TimeSpan.FromMilliseconds(20));
        using var _s = store;
        pusher.Detach();
        Add(store, pusher, "E1");
        await Task.Delay(150);
        Assert.Empty(frames.List);
        Assert.Equal(0, pusher.InFlight.Count);
    }

    [Fact]
    public async Task State_changes_are_debounced_into_one_signal()
    {
        var notifier = new StateChangeNotifier();
        int fired = 0;
        _ = new StateChangeDebouncer(notifier, () => Interlocked.Increment(ref fired), TimeSpan.FromMilliseconds(400));
        for (int i = 0; i < 5; i++) { notifier.Notify(); await Task.Delay(1); }
        Assert.Equal(0, Volatile.Read(ref fired));
        await WaitFor(() => Volatile.Read(ref fired) == 1);
        await Task.Delay(200);
        Assert.Equal(1, Volatile.Read(ref fired));
        notifier.Notify();
        await WaitFor(() => Volatile.Read(ref fired) == 2);
    }

    private sealed class Sink : IEventSink
    {
        public List<(string Type, string? Sid, JsonObject Data)> Events { get; } = [];
        public void Emit(string type, string? userSid, JsonObject data) { lock (Events) Events.Add((type, userSid, data)); }
    }

    [Fact]
    public void Net_domain_window_is_one_minute_and_first_connection_is_emitted_at_once()
    {
        var options = new NetGuardOptions();
        Assert.Equal(TimeSpan.FromMinutes(1), options.DomainWindow);
        var clock = new FakeClock(T0);
        var sink = new Sink();
        var agg = new DomainAggregator(sink, clock, options);

        agg.RecordConnection("S", "chrome.exe", "a.example", true);
        Assert.Single(sink.Events);
        Assert.Equal(1L, (long)sink.Events[0].Data["connections"]!);
        agg.RecordConnection("S", "chrome.exe", "a.example", true);   // same window: folded
        agg.RecordConnection("S", "chrome.exe", "a.example", true);
        Assert.Single(sink.Events);
        agg.RecordConnection("S", "chrome.exe", "b.example", true);   // new host: emitted
        Assert.Equal(2, sink.Events.Count);

        agg.RecordBytes("S", "chrome.exe", "a.example", true, 10, 20);
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(1, agg.Flush());                                  // b.example had only its first-seen record
        var rec = sink.Events[2].Data;
        Assert.Equal("a.example", (string)rec["host"]!);
        Assert.Equal(2L, (long)rec["connections"]!);                     // 3 total - 1 already emitted
        Assert.Equal(20L, (long)rec["bytesIn"]!);

        agg.RecordConnection("S", "chrome.exe", "a.example", true);   // next window: first-seen again
        Assert.Equal(4, sink.Events.Count);
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public List<string> Bodies { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Bodies.Add(await request.Content!.ReadAsStringAsync(ct));
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"accepted\":1,\"rejected\":[]}") };
        }
    }
}
