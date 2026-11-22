using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;
using MinControl.Core.Crypto;
using MinControl.Core.Policy;
using MinControl.Core.Protocol;
using MinControl.Core.Storage;
using MinControl.Core.Util;

namespace MinControl.Core.Policies;

/// <summary>
/// Holds the current verified policy (I3: enforced offline from state.db). On construction the stored envelope is
/// re-verified (pinned key + signature + device) and re-parsed, so a tampered state.db cannot inject a policy.
/// </summary>
public sealed class PolicyProvider : IPolicyProvider
{
    private readonly StateStore _store;
    private readonly EnvelopeVerifier _verifier;
    private readonly IClock _clock;
    private readonly ILogger _log;
    private DevicePolicy? _current;

    public PolicyProvider(StateStore store, EnvelopeVerifier verifier, IClock clock, ILogger<PolicyProvider>? log = null)
    {
        _store = store; _verifier = verifier; _clock = clock;
        _log = log ?? (ILogger)NullLogger.Instance;
        _current = LoadStored();
    }

    public DevicePolicy? Current => Volatile.Read(ref _current);
    public long CurrentSeq { get; private set; }
    /// <summary>True when state.db held a policy that failed re-verification at startup (possible tampering).</summary>
    public bool StoredPolicyRejected { get; private set; }
    public event EventHandler<DevicePolicy>? PolicyChanged;

    /// <summary>Policy timezone, or the default Asia/Ho_Chi_Minh when no policy is present.</summary>
    public TimeZoneInfo TimeZone => TimeZones.TryFind(Current?.Timezone ?? "Asia/Ho_Chi_Minh") ?? TimeZoneInfo.Utc;

    public UserPolicy? ForUser(string sid) =>
        Current is { } p && p.Users.TryGetValue(sid, out var u) ? u : null;

    /// <summary>Parses + validates the body of a verified policy envelope and makes it current. Returns (error, detail) on rejection.</summary>
    public (string? Error, string? Detail) Apply(VerifiedEnvelope env)
    {
        if (env.Body.Kind != "policy") return (VerifyErrors.InvalidBody, "not a policy envelope");
        var parsed = PolicyParser.Parse(env.Body.Body);
        if (!parsed.Ok) return (parsed.Error, parsed.Detail);
        var policy = parsed.Policy!;
        _store.SavePolicy(new StoredPolicy(policy.Version, env.Body.Seq,
            JsonSerializer.Serialize(env.Envelope, ProtocolJson.Options), env.Body.Body.GetRawText(), Time.Utc(_clock.UtcNow)));
        Volatile.Write(ref _current, policy);
        CurrentSeq = env.Body.Seq;
        _log.LogInformation("policy v{Version} (seq {Seq}) applied", policy.Version, env.Body.Seq);
        PolicyChanged?.Invoke(this, policy);
        return (null, null);
    }

    private DevicePolicy? LoadStored()
    {
        var stored = _store.GetPolicy();
        if (stored is null) return null;
        try
        {
            var env = JsonSerializer.Deserialize<SignedEnvelope>(stored.EnvelopeJson, ProtocolJson.Options);
            if (env is null) return null;
            var v = _verifier.VerifyStored(env);
            if (!v.Ok || v.Envelope!.Body.Kind != "policy")
            {
                _log.LogError("stored policy failed re-verification ({Error}); ignoring it", v.Error);
                StoredPolicyRejected = true;
                return null;
            }
            var parsed = PolicyParser.Parse(v.Envelope.Body.Body);
            if (!parsed.Ok) { _log.LogError("stored policy invalid: {Detail}", parsed.Detail); StoredPolicyRejected = true; return null; }
            CurrentSeq = v.Envelope.Body.Seq;
            return parsed.Policy;
        }
        catch (Exception e) when (e is JsonException or NotSupportedException)
        {
            _log.LogError(e, "stored policy unreadable");
            return null;
        }
    }
}
