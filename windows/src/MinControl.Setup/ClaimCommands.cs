using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using MinControl.Core.Crypto;
using MinControl.Core.Storage;
using MinControl.Core.Util;
using MinControl.Setup;

/// <summary>
/// QR pairing (API.md §10), used by the installer bootstrapper and the connect tool (they parse the last stdout
/// line, a JSON object):
///   claim-start [--force]
///       Creates a pending device key (device.pending.key: an existing enrolment keeps working until the phone
///       approves), POST /v1/enroll/start, stores claim.json and prints
///       {"status":"ok","claimId","code","expiresAt","fingerprint","qr"} | {"status":"already_enrolled","deviceId"}
///       | {"status":"error","reason","message"}.
///   claim-wait &lt;claimId&gt; [--timeout &lt;s&gt;] [--restart-service]
///       Polls GET /v1/enroll/claim/&lt;id&gt; every 2 s (signed with the pending key) until approved / expired /
///       rejected / timeout. Approved: pending key becomes device.key, master keys pinned exactly like enroll,
///       outcome recorded (EnrollStatus), service (re)started. Prints {"status":"approved|pending|expired|rejected|error",…}.
/// </summary>
internal static partial class Cli
{
    private const string PendingKeyFile = "device.pending.key";
    private const string ClaimFile = "claim.json";
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);

    private static int PrintJson(JsonObject o, int exitCode)
    {
        Console.WriteLine(o.ToJsonString());
        return exitCode;
    }

    private static int ClaimError(string reason, string message, string? detail = null) =>
        PrintJson(new JsonObject { ["status"] = "error", ["reason"] = reason, ["message"] = message, ["detail"] = detail }, 1);

    /// <summary>Server base URI from config.json (written by install / the MSI).</summary>
    private static Uri? ConfiguredServer(DataPaths paths, bool allowHttp)
    {
        var s = File.Exists(AgentConfig.PathIn(paths.Root)) ? AgentConfig.Load(paths.Root).ServerUrl : null;
        return Uri.TryCreate(s, UriKind.Absolute, out var u) && (u.Scheme == "https" || (allowHttp && u.Scheme == "http")) ? u : null;
    }

    /// <summary>First 12 hex chars of SHA-256(raw device public key): shown on the PC and on the phone.</summary>
    internal static string Fingerprint(byte[] pub) => Convert.ToHexString(SHA256.HashData(pub))[..12].ToLowerInvariant();

    private static async Task<int> ClaimStartAsync(DataPaths paths, bool force, bool allowHttp)
    {
        if (!IsElevated()) return RequireElevation();
        if (ConfiguredServer(paths, allowHttp) is not { } baseUri) return ClaimError("no_server", EnrollMessages.NoServer);

        paths.EnsureExists();
        paths.ApplyRestrictedAcl();   // I7 before any key is written
        using (var store = new StateStore(paths.StateDb))
        {
            if (store.GetMeta(StateStore.MetaKeys.DeviceId) is { } existing && !force)
                return PrintJson(new JsonObject { ["status"] = "already_enrolled", ["deviceId"] = existing, ["message"] = EnrollMessages.AlreadyEnrolled }, 0);
        }

        using var pending = new DeviceIdentity(Path.Combine(paths.Root, PendingKeyFile), new DpapiMachineKeyProtector());
        var pub = pending.CreateNew();
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            using var resp = await http.PostAsync(new Uri(baseUri, "/v1/enroll/start"), JsonContent.Create(DeviceInfo(pub, LocalUsers.Enumerate())));
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
                return ServerErrorCode(text) == "no_master"
                    ? ClaimError("no_master", EnrollMessages.NoMaster, $"HTTP {(int)resp.StatusCode} {text}")
                    : ClaimError("server", EnrollMessages.Server, $"HTTP {(int)resp.StatusCode} {text}");
            var r = JsonNode.Parse(text);
            var claimId = (string?)r?["claimId"];
            var code = (string?)r?["code"];
            var expiresAt = (string?)r?["expiresAt"];
            if (claimId is null || !Base64Url.TryDecode(claimId, out var cid) || cid.Length != 16 || expiresAt is null)
                return ClaimError("server", EnrollMessages.Server, "malformed enroll/start response");

            var fp = Fingerprint(pub);
            File.WriteAllText(Path.Combine(paths.Root, ClaimFile),
                new JsonObject { ["claimId"] = claimId, ["expiresAt"] = expiresAt, ["server"] = baseUri.GetLeftPart(UriPartial.Authority) }.ToJsonString(),
                new UTF8Encoding(false));
            return PrintJson(new JsonObject
            {
                ["status"] = "ok",
                ["claimId"] = claimId,
                ["code"] = code is { Length: 8 } ? code[..4] + "-" + code[4..] : code,
                ["expiresAt"] = expiresAt,
                ["fingerprint"] = fp,
                ["qr"] = PairingQr.Build(baseUri.GetLeftPart(UriPartial.Authority), claimId, fp),
            }, 0);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
        {
            return ClaimError("network", EnrollMessages.Network, e.Message);
        }
    }

    private static async Task<int> ClaimWaitAsync(DataPaths paths, string claimId, int timeoutSec, bool restartService, bool mirrorToRegistry)
    {
        if (!IsElevated()) return RequireElevation();
        var claimPath = Path.Combine(paths.Root, ClaimFile);
        var pendingPath = Path.Combine(paths.Root, PendingKeyFile);
        if (!File.Exists(claimPath) || !File.Exists(pendingPath)) return ClaimError("no_claim", "Mã QR đã cũ. Đang tạo mã mới.");
        var claim = JsonNode.Parse(File.ReadAllText(claimPath));
        if ((string?)claim?["claimId"] != claimId) return ClaimError("no_claim", "Mã QR đã cũ. Đang tạo mã mới.");
        var baseUri = new Uri((string)claim!["server"]!);

        using var pending = new DeviceIdentity(pendingPath, new DpapiMachineKeyProtector());
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(Math.Clamp(timeoutSec, 2, 900));
        string? lastError = null;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
                var sig = Base64Url.Encode(pending.Sign(Encoding.UTF8.GetBytes($"poll|{claimId}|{ts}")));
                using var resp = await http.GetAsync(new Uri(baseUri, $"/v1/enroll/claim/{Uri.EscapeDataString(claimId)}?ts={ts}&sig={sig}"));
                var text = await resp.Content.ReadAsStringAsync();
                switch (resp.StatusCode)
                {
                    case HttpStatusCode.Accepted:
                        lastError = null;
                        break;
                    case HttpStatusCode.OK:
                        return Approved(paths, text, baseUri, pendingPath, claimPath, restartService, mirrorToRegistry);
                    case HttpStatusCode.Gone:
                        var why = ServerErrorCode(text) == "rejected" ? "rejected" : "expired";
                        File.Delete(claimPath);
                        if (why == "rejected")
                        {
                            EnrollStatus.Write(paths, EnrollOutcome.Fail("rejected", EnrollMessages.Rejected), claimId, mirrorToRegistry);
                            return PrintJson(new JsonObject { ["status"] = "rejected", ["message"] = EnrollMessages.Rejected }, 1);
                        }
                        return PrintJson(new JsonObject { ["status"] = "expired", ["message"] = EnrollMessages.Expired }, 1);
                    default:
                        lastError = $"HTTP {(int)resp.StatusCode} {text}";
                        break;
                }
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException)
            {
                lastError = e.Message;   // transient: keep polling until the deadline
            }
            await Task.Delay(PollInterval);
        }
        return PrintJson(new JsonObject
        {
            ["status"] = "pending",
            ["message"] = lastError is null ? "" : EnrollMessages.Network,
            ["detail"] = lastError,
        }, 0);
    }

    private static int Approved(DataPaths paths, string text, Uri baseUri, string pendingPath, string claimPath, bool restartService, bool mirrorToRegistry)
    {
        EnrollOutcome outcome;
        try
        {
            var (er, pinned) = ParseEnrollResponse(text);
            // key first (atomic rename), then the pinned state: the service only uses the identity once DeviceId is set
            File.Move(pendingPath, paths.DeviceKey, overwrite: true);
            using (var store = new StateStore(paths.StateDb)) CommitEnrollment(store, er, pinned, baseUri);
            File.Delete(claimPath);
            outcome = new EnrollOutcome(true, "ok", EnrollMessages.Ok, er.DeviceId);
            Console.Error.WriteLine($"enrolled as {er.DeviceId}; pinned {string.Join(", ", pinned.Select(p => p.KeyId))}");
        }
        catch (Exception e) when (e is InvalidOperationException or JsonException or IOException or UnauthorizedAccessException)
        {
            outcome = EnrollOutcome.Fail("error", EnrollMessages.Error, e.Message);
        }
        EnrollStatus.Write(paths, outcome, null, mirrorToRegistry);
        if (!outcome.Ok) return ClaimError(outcome.Reason, outcome.Message, outcome.Detail);

        if (restartService && SystemTools.ServiceState() is { } state)
        {
            if (state == "RUNNING") SystemTools.StopService(TimeSpan.FromSeconds(45));
            SystemTools.StartService();
        }
        return PrintJson(new JsonObject { ["status"] = "approved", ["deviceId"] = outcome.DeviceId, ["message"] = EnrollMessages.Ok }, 0);
    }
}
