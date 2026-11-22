using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using MinControl.Core.Abstractions;
using MinControl.Core.Commands;
using MinControl.Core.Crypto;
using MinControl.Core.Policies;
using MinControl.Core.Protocol;
using MinControl.Core.ScreenTime;
using MinControl.Core.Storage;
using MinControl.Core.Telemetry;
using MinControl.Core.Util;
using NSec.Cryptography;

namespace MinControl.Core.Tests;

internal sealed class FakeClock(DateTimeOffset start) : IClock
{
    public DateTimeOffset UtcNow { get; set; } = start;
    public long MonotonicMs { get; set; }

    public void Advance(TimeSpan d) { UtcNow += d; MonotonicMs += (long)d.TotalMilliseconds; }
}

internal sealed class NoopKeyProtector : IKeyProtector
{
    public byte[] Protect(byte[] secret) => (byte[])secret.Clone();
    public byte[] Unprotect(byte[] blob) => (byte[])blob.Clone();
}

/// <summary>A master signing key as the phone would hold it.</summary>
internal sealed class MasterKey : IDisposable
{
    private readonly Key? _ed;
    private readonly ECDsa? _ec;
    public string Alg { get; }
    public byte[] PublicKey { get; }
    public string KeyId => Signatures.KeyId(PublicKey);

    private MasterKey(string alg)
    {
        Alg = alg;
        if (alg == Signatures.Ed25519)
        {
            _ed = Key.Create(SignatureAlgorithm.Ed25519);
            PublicKey = _ed.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        }
        else
        {
            _ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var q = _ec.ExportParameters(false).Q;
            PublicKey = [0x04, .. q.X!, .. q.Y!];
        }
    }

    public static MasterKey Ed25519() => new(Signatures.Ed25519);
    public static MasterKey Es256() => new(Signatures.Es256);

    public byte[] Sign(byte[] data) => _ed is not null
        ? SignatureAlgorithm.Ed25519.Sign(_ed, data)
        : _ec!.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    public PinnedKey Pinned => new(KeyId, Alg, PublicKey);

    public void Dispose() { _ed?.Dispose(); _ec?.Dispose(); }
}

internal static class TestData
{
    public const string DeviceId = "01JDQ3Z8K4M2N6P8R0S2T4V6W8";
    public const string OtherDeviceId = "01JDQ3Z8K4M2N6P8R0S2T4V6W9";
    public const string Sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    public const string AdminSid = "S-1-5-21-1111111111-2222222222-3333333333-500";

    private static string? _protocolDir;
    public static string ProtocolDir => _protocolDir ??= Find();

    private static string Find()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var p = Path.Combine(dir.FullName, "protocol");
            if (Directory.Exists(p) && Directory.GetFiles(p, "*.schema.json").Length > 0) return p;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("protocol/ not found");
    }

    public static string Fixture(string stem, string kind, string file) =>
        File.ReadAllText(Path.Combine(ProtocolDir, "fixtures", stem, kind, file));

    /// <summary>protocol/fixtures/policy/valid/basic.json as a mutable node.</summary>
    public static JsonObject BasicPolicy() => JsonNode.Parse(Fixture("policy", "valid", "basic.json"))!.AsObject();

    public static JsonObject User(JsonObject policy) => policy["users"]![Sid]!.AsObject();

    public static string Envelope(MasterKey key, string kind, long seq, JsonNode body, DateTimeOffset issuedAt,
        DateTimeOffset? expiresAt = null, string deviceId = DeviceId, string? keyIdOverride = null, MasterKey? signWith = null)
    {
        var signed = new JsonObject
        {
            ["deviceId"] = deviceId,
            ["kind"] = kind,
            ["seq"] = seq,
            ["issuedAt"] = Time.Utc(issuedAt),
            ["expiresAt"] = Time.Utc(expiresAt ?? issuedAt.AddHours(1)),
            ["body"] = body.DeepClone(),
        };
        var payload = Encoding.UTF8.GetBytes(signed.ToJsonString());
        var env = new SignedEnvelope(1, key.Alg, keyIdOverride ?? key.KeyId, Base64Url.Encode(payload),
            Base64Url.Encode((signWith ?? key).Sign(payload)));
        return JsonSerializer.Serialize(env, ProtocolJson.Options);
    }

    public static SignedEnvelope Parse(string envelopeJson) =>
        JsonSerializer.Deserialize<SignedEnvelope>(envelopeJson, ProtocolJson.Options)!;
}

/// <summary>Everything Core needs, wired by hand over an in-memory store.</summary>
internal sealed class CoreHarness : IDisposable
{
    public FakeClock Clock { get; }
    public StateStore Store { get; } = new(":memory:");
    public MasterKey Master { get; } = MasterKey.Ed25519();
    public EnvelopeVerifier Verifier { get; }
    public PolicyProvider Policy { get; }
    public EventSink Events { get; }
    public ScreenTimeEngine Engine { get; }
    public CommandDispatcher Commands { get; }
    public FakeSessionActions Session { get; } = new();
    public FakeUserDirectory Users { get; } = new();
    private long _seq;

    public CoreHarness(DateTimeOffset now)
    {
        Clock = new FakeClock(now);
        Store.SetMeta(StateStore.MetaKeys.DeviceId, TestData.DeviceId);
        Store.ReplaceMasterKeys([Master.Pinned]);
        Verifier = new EnvelopeVerifier(Store, Clock);
        Policy = new PolicyProvider(Store, Verifier, Clock);
        Events = new EventSink(Store, Clock);
        Engine = new ScreenTimeEngine(Store, Policy, Clock);
        Commands = new CommandDispatcher(Store, Policy, Clock, new ApprovalStore(Store, Clock), () => Session, null, () => Users);
    }

    public void ApplyPolicy(JsonObject policy)
    {
        var env = TestData.Parse(TestData.Envelope(Master, "policy", ++_seq, policy, Clock.UtcNow));
        var v = Verifier.Verify(env);
        if (!v.Ok) throw new InvalidOperationException("policy envelope rejected: " + v.Error);
        var (err, detail) = Policy.Apply(v.Envelope!);
        if (err is not null) throw new InvalidOperationException($"policy rejected: {err} {detail}");
    }

    private long _cmdSeq;
    public Task<CommandAck> CommandAsync(JsonObject body)
    {
        body["commandId"] ??= UlidGenerator.Shared.New(Clock.UtcNow);
        var env = TestData.Parse(TestData.Envelope(Master, "command", ++_cmdSeq, body, Clock.UtcNow));
        var v = Verifier.Verify(env);
        if (!v.Ok) throw new InvalidOperationException("command envelope rejected: " + v.Error);
        return Commands.DispatchAsync(v.Envelope!, CancellationToken.None);
    }

    public void Dispose() { Engine.Dispose(); Store.Dispose(); Master.Dispose(); }
}

internal sealed class FakeSessionActions : ISessionActions
{
    public List<string> Calls { get; } = [];
    public bool KillResult { get; set; } = true;
    public Task LogoffAsync(string sid, string reason, CancellationToken ct) { Calls.Add($"logoff {sid}"); return Task.CompletedTask; }
    public Task ShowWarningAsync(string sid, int remainingMin, CancellationToken ct) { Calls.Add($"warn {sid} {remainingMin}"); return Task.CompletedTask; }
    public Task ShowLockOverlayAsync(string sid, string reason, int graceSec, CancellationToken ct) { Calls.Add($"lock {sid} {graceSec}"); return Task.CompletedTask; }
    public Task ShowMessageAsync(string sid, string text, CancellationToken ct) { Calls.Add($"message {sid} {text}"); return Task.CompletedTask; }
    public Task ShowBlockedNoticeAsync(string sid, string title, string reason, CancellationToken ct) { Calls.Add($"blocked {sid} {title} | {reason}"); return Task.CompletedTask; }
    public Task<bool> KillProcessAsync(string sid, int pid, string? expectedExe, CancellationToken ct) { Calls.Add($"kill {sid} {pid}"); return Task.FromResult(KillResult); }
    public ScreenCapture? Capture { get; set; }
    public Task<ScreenCapture?> CaptureScreenAsync(string? sid, int maxWidth, int jpegQuality, CancellationToken ct) => Task.FromResult(Capture);
}

internal sealed class FakeUserDirectory : IUserDirectory
{
    public HashSet<string> Admins { get; } = new(StringComparer.Ordinal);
    public bool IsManaged(string sid) => !Admins.Contains(sid);
    public bool IsAdministrator(string sid) => Admins.Contains(sid);
    public IReadOnlyCollection<string> ManagedSids => [];
    public string? SidOfProcess(int pid) => null;
    public string? ProfilePath(string sid) => null;
}
