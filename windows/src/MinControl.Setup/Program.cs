using System.Net.Http.Json;
using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using MinControl.Core.Crypto;
using MinControl.Core.Protocol;
using MinControl.Core.Storage;
using MinControl.Core.Util;
using MinControl.Setup;

// MinControl.Setup — run elevated (the exe manifest requests UAC).
//   install  --server <https-url> [--chrome-ext <id>] [--edge-ext <id>] [--from-msi]
//       Post-MSI configuration: writes %ProgramData%\MinControl\config.json (SYSTEM/Admins-only ACL) and the
//       native-messaging host manifest next to MinControl.NativeHost.exe. The MSI runs it with its properties.
//   enroll <code> [--server <https-url>] [--force] [--from-msi] [--attempt <id>] [--restart-service]
//       Server defaults to config.json ServerUrl. Every run records its outcome in
//       %ProgramData%\MinControl\enroll-status.json + HKLM\SOFTWARE\MinControl (EnrollStatus) for the MSI Finish
//       dialog and the connect tool. --from-msi: "already enrolled" counts as success (re-install / upgrade).
//       --restart-service: (re)start the MinControl service after a successful enrolment (connect tool).
//   claim-start [--force] / claim-wait <claimId> [--timeout <s>] [--restart-service]
//       QR pairing (API.md §10): the parent scans a QR code with the master app and approves (ClaimCommands.cs).
//   connect                                                  opens the connect tool (MinControl.Connect.exe, QR screen)
//   status                                                   (read-only)
//   uninstall --yes [--purge] [--from-msi]
//       Stops the service, removes WFP filters, browser policies (all profiles) + native host registration,
//       SafeBoot keys. Keeps state.db/device.key unless --purge. Without --from-msi it then removes the MSI
//       product (msiexec /x) or, for a non-MSI install, deletes the service.
//   unenroll --yes                                           (wipes identity + state only)
// Common: [--data-dir <dir>] (tests only; default %ProgramData%\MinControl).
// Exit codes: 0 ok, 1 failure, 2 usage, 3 not elevated.

return await Cli.RunAsync(args);

internal static partial class Cli
{
    private static readonly string AgentVersion =
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";

    /// <summary>Install folder = the folder of this exe (MSI puts Setup next to the Service).</summary>
    private static string InstallDir => AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);

    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0) return Usage();
        var dataDir = Opt(args, "--data-dir");
        var paths = new DataPaths(dataDir);
        try
        {
            switch (args[0])
            {
                case "install":
                    return Install(paths, Opt(args, "--server"), Opt(args, "--chrome-ext"), Opt(args, "--edge-ext"),
                        args.Contains("--insecure-http"));
                case "enroll":
                    if (args.Length < 2 || args[1].StartsWith("--", StringComparison.Ordinal)) return Usage();
                    return await EnrollCommandAsync(paths, args[1], Opt(args, "--server"), args.Contains("--force"),
                        args.Contains("--insecure-http"), args.Contains("--from-msi"), args.Contains("--restart-service"),
                        Opt(args, "--attempt"), mirrorToRegistry: dataDir is null);
                case "claim-start":
                    return await ClaimStartAsync(paths, args.Contains("--force"), args.Contains("--insecure-http"));
                case "claim-wait":
                    if (args.Length < 2 || args[1].StartsWith("--", StringComparison.Ordinal)) return Usage();
                    return await ClaimWaitAsync(paths, args[1], int.TryParse(Opt(args, "--timeout"), out var t) ? t : 30,
                        args.Contains("--restart-service"), mirrorToRegistry: dataDir is null);
                case "connect":
                    return LaunchConnectTool(args.Skip(1).FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal)));
                case "status":
                    return Status(paths);
                case "uninstall":
                    if (!args.Contains("--yes")) { Console.Error.WriteLine("uninstall removes all enforcement from this PC; pass --yes"); return 2; }
                    return await UninstallAsync(paths, args.Contains("--purge"), args.Contains("--from-msi"));
                case "unenroll":
                    if (!args.Contains("--yes")) { Console.Error.WriteLine("unenroll wipes the device identity and state; pass --yes"); return 2; }
                    return Unenroll(paths);
                default:
                    return Usage();
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("error: " + e.Message);
            return 1;
        }
    }

    private static int Usage()
    {
        Console.Error.WriteLine("""
            usage (elevated):
              MinControl.Setup install --server <https://…> [--chrome-ext <id>] [--edge-ext <id>]
              MinControl.Setup enroll <CODE> [--server <https://…>] [--force] [--restart-service]
              MinControl.Setup claim-start [--force]   (QR pairing, JSON output; see ClaimCommands.cs)
              MinControl.Setup claim-wait <claimId> [--timeout <s>] [--restart-service]
              MinControl.Setup connect                 (window: QR code to scan with the master app)
              MinControl.Setup status
              MinControl.Setup uninstall --yes [--purge]
              MinControl.Setup unenroll --yes
            """);
        return 2;
    }

    private static string? Opt(string[] args, string name)
    {
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    private static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return id.IsSystem || new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static int RequireElevation()
    {
        Console.Error.WriteLine("run this command from an elevated (Administrator) prompt");
        return 3;
    }

    // ------------------------------------------------------------------------------------------------ install

    private static int Install(DataPaths paths, string? server, string? chromeExt, string? edgeExt, bool allowHttp)
    {
        if (!IsElevated()) return RequireElevation();
        paths.EnsureExists();
        paths.ApplyRestrictedAcl();   // I7 before anything is written
        var config = AgentConfig.Load(paths.Root);
        // Empty values mean "keep" (the MSI passes empty properties on upgrades / repairs).
        if (!string.IsNullOrWhiteSpace(server)) config.ServerUrl = server.Trim().TrimEnd('/');
        if (!string.IsNullOrWhiteSpace(chromeExt)) config.ChromeExtensionId = chromeExt.Trim().ToLowerInvariant();
        if (!string.IsNullOrWhiteSpace(edgeExt)) config.EdgeExtensionId = edgeExt.Trim().ToLowerInvariant();
        if (config.Validate(allowHttp) is { } err) { Console.Error.WriteLine(err); return 2; }
        config.Save(paths.Root);
        Console.WriteLine($"config         : {AgentConfig.PathIn(paths.Root)}");
        Console.WriteLine($"server         : {config.ServerUrl}");
        Console.WriteLine($"chrome ext     : {(string.IsNullOrEmpty(config.ChromeExtensionId) ? "(none)" : config.ChromeExtensionId)}");
        Console.WriteLine($"edge ext       : {(string.IsNullOrEmpty(config.EdgeExtensionId) ? "(none)" : config.EdgeExtensionId)}");

        // Native host manifest: same content/path the Service writes (BrowserPolicyWriter.ApplyMachine), so the
        // extension can connect even before the first policy arrives. The HKLM registration is done by the MSI.
        var browser = Cleanup.BrowserOptionsFor(config, InstallDir);
        if (File.Exists(browser.NativeHostExePath))
        {
            var manifestPath = Path.Combine(InstallDir, browser.NativeHostName + ".json");
            File.WriteAllText(manifestPath, new MinControl.Browser.Policy.BrowserPolicyMapper(browser).BuildNativeHostManifest(),
                new System.Text.UTF8Encoding(false));
            Console.WriteLine($"native host    : {manifestPath}");
        }
        else Console.WriteLine($"native host    : skipped ({browser.NativeHostExePath} not found - not an installed copy)");

        Console.WriteLine($"ACL restricted : {paths.IsAclRestricted()}");
        Console.WriteLine("Next: MinControl.Setup enroll <CODE>   (pairing code from the master app)");
        return 0;
    }

    // ------------------------------------------------------------------------------------------------ enroll

    private sealed record EnrollKey(string KeyId, string Alg, string PublicKey);
    private sealed record EnrollResponse(string DeviceId, string ServerTime, IReadOnlyList<EnrollKey> MasterKeys, string MasterSealPubKey);

    /// <summary>Runs one enrolment, records the outcome (<see cref="EnrollStatus"/>) and maps it to an exit code.</summary>
    private static async Task<int> EnrollCommandAsync(DataPaths paths, string rawCode, string? serverArg, bool force, bool allowHttp,
        bool fromMsi, bool restartService, string? attempt, bool mirrorToRegistry)
    {
        if (!IsElevated()) return RequireElevation();
        EnrollOutcome outcome;
        try
        {
            var server = !string.IsNullOrWhiteSpace(serverArg) ? serverArg
                : File.Exists(AgentConfig.PathIn(paths.Root)) ? AgentConfig.Load(paths.Root).ServerUrl : null;
            outcome = string.IsNullOrWhiteSpace(server)
                ? EnrollOutcome.Fail("no_server", EnrollMessages.NoServer, "no --server given and config.json has no ServerUrl (run install first)")
                : await EnrollAsync(paths, rawCode, server, force, allowHttp);
        }
        catch (HttpRequestException e) { outcome = EnrollOutcome.Fail("network", EnrollMessages.Network, e.Message); }
        catch (TaskCanceledException e) { outcome = EnrollOutcome.Fail("network", EnrollMessages.Network, "timeout: " + e.Message); }
        catch (Exception e) { outcome = EnrollOutcome.Fail("error", EnrollMessages.Error, e.Message); }

        EnrollStatus.Write(paths, outcome, attempt, mirrorToRegistry);

        if (outcome.Ok && restartService && SystemTools.ServiceState() is { } state)
        {
            // The service polls for an identity once a minute; a restart makes it connect right away.
            if (state == "RUNNING" && !SystemTools.StopService(TimeSpan.FromSeconds(45)))
                Console.Error.WriteLine("warning: service did not stop within 45 s");
            var (rc, output) = SystemTools.StartService();
            Console.WriteLine(rc == 0 ? "service        : started" : $"warning: service start returned {rc} {output}");
        }

        if (outcome.Ok) Console.WriteLine(outcome.Reason == "already_enrolled" ? $"already enrolled as {outcome.DeviceId}" : $"enrolled as {outcome.DeviceId}");
        else Console.Error.WriteLine($"enrolment failed ({outcome.Reason}): {outcome.Detail ?? outcome.Message}");
        return outcome switch
        {
            { Ok: true, Reason: "already_enrolled" } when !fromMsi => 2,   // CLI: tell the operator to use --force
            { Ok: true } => 0,
            { Reason: "bad_format" or "no_server" } => 2,
            _ => 1,
        };
    }

    /// <summary>Normalises "xxxx-xxxx" / "xxxxxxxx" (any case, spaces ignored); null when it is not 8 Crockford chars.</summary>
    internal static string? NormalizeCode(string raw)
    {
        var code = new string(raw.Where(c => c != '-' && !char.IsWhiteSpace(c)).ToArray()).ToUpperInvariant();
        return code.Length == 8 && code.All(c => "0123456789ABCDEFGHJKMNPQRSTVWXYZ".Contains(c)) ? code : null;
    }

    private static async Task<EnrollOutcome> EnrollAsync(DataPaths paths, string rawCode, string server, bool force, bool allowHttp)
    {
        if (NormalizeCode(rawCode) is not { } code)
            return EnrollOutcome.Fail("bad_format", EnrollMessages.BadFormat, "pairing code must be 8 Crockford base32 characters (XXXX-XXXX)");
        if (!Uri.TryCreate(server, UriKind.Absolute, out var baseUri) || !(baseUri.Scheme == "https" || (allowHttp && baseUri.Scheme == "http")))
            return EnrollOutcome.Fail("no_server", EnrollMessages.NoServer, "--server must be an absolute https:// URL");

        paths.EnsureExists();
        paths.ApplyRestrictedAcl();   // I7: SYSTEM + Administrators only, before any secret is written

        using var store = new StateStore(paths.StateDb);
        if (store.GetMeta(StateStore.MetaKeys.DeviceId) is { } existing && !force)
            return new EnrollOutcome(true, "already_enrolled", EnrollMessages.AlreadyEnrolled, existing,
                $"already enrolled as {existing}; use --force to re-enrol (wipes local state)");

        var users = LocalUsers.Enumerate();
        Console.WriteLine("Local users:");
        foreach (var u in users) Console.WriteLine($"  {u.Name,-24} {u.Sid}{(u.IsAdmin ? "  (admin - can never be managed)" : "")}");

        // --force on an enrolled PC: keep the old key until the server accepted the new one, so a wrong or expired
        // code never breaks a working enrolment.
        byte[]? previousKey = File.Exists(paths.DeviceKey) ? File.ReadAllBytes(paths.DeviceKey) : null;
        using var identity = new DeviceIdentity(paths, new DpapiMachineKeyProtector());
        var committed = false;
        try
        {
            var pub = identity.CreateNew();
            var request = DeviceInfo(pub, users);
            request["code"] = code;

            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            using var resp = await http.PostAsync(new Uri(baseUri, "/v1/enroll"), JsonContent.Create(request));
            var text = await resp.Content.ReadAsStringAsync();
            if (!resp.IsSuccessStatusCode)
            {
                var detail = $"HTTP {(int)resp.StatusCode} {text}";
                var error = ServerErrorCode(text);
                return ((int)resp.StatusCode, error) switch
                {
                    (_, "invalid_code") or (403, null) => EnrollOutcome.Fail("invalid_code", EnrollMessages.InvalidCode, detail),
                    (_, "no_master") => EnrollOutcome.Fail("no_master", EnrollMessages.NoMaster, detail),
                    _ => EnrollOutcome.Fail("server", EnrollMessages.Server, detail),
                };
            }
            var (er, pinned) = ParseEnrollResponse(text);
            CommitEnrollment(store, er, pinned, baseUri);
            committed = true;

            Console.WriteLine($"Enrolled as {er.DeviceId}. Pinned master keys: {string.Join(", ", pinned.Select(p => $"{p.KeyId} ({p.Alg})"))}");
            Console.WriteLine("Compare the fingerprints with the master app, then choose managed users there.");
            return new EnrollOutcome(true, "ok", EnrollMessages.Ok, er.DeviceId);
        }
        finally
        {
            if (!committed)
            {
                // previous identity back (or none): a failed --force leaves the old enrolment working
                if (previousKey is not null) File.WriteAllBytes(paths.DeviceKey, previousKey);
                else identity.Delete();
            }
        }
    }

    /// <summary>Device description sent with /v1/enroll and /v1/enroll/start (API.md §1, §10).</summary>
    private static JsonObject DeviceInfo(byte[] pub, IReadOnlyList<LocalUser> users)
    {
        var osv = Environment.OSVersion.Version;
        return new JsonObject
        {
            ["devicePubKey"] = Base64Url.Encode(pub),
            ["hostname"] = Environment.MachineName,
            ["osVersion"] = $"{osv.Major}.{osv.Minor}.{osv.Build}",
            ["agentVersion"] = AgentVersion,
            ["localUsers"] = new JsonArray(users.Select(u => (JsonNode)new JsonObject { ["sid"] = u.Sid, ["name"] = u.Name, ["isAdmin"] = u.IsAdmin }).ToArray()),
        };
    }

    /// <summary>Validates an enrolment response (/v1/enroll 201 or an approved claim): deviceId, sign keys, seal key.</summary>
    private static (EnrollResponse Response, List<PinnedKey> Pinned) ParseEnrollResponse(string text)
    {
        var er = JsonSerializer.Deserialize<EnrollResponse>(text, ProtocolJson.Options) ?? throw new InvalidOperationException("empty enrol response");
        if (!UlidGenerator.IsValid(er.DeviceId)) throw new InvalidOperationException("server returned an invalid deviceId");
        var pinned = new List<PinnedKey>();
        foreach (var k in er.MasterKeys ?? [])
        {
            if (!Base64Url.TryDecode(k.PublicKey, out var kb) || !Signatures.IsValidPublicKey(k.Alg, kb))
                throw new InvalidOperationException($"master key {k.KeyId} is malformed");
            if (Signatures.KeyId(kb) != k.KeyId)
                throw new InvalidOperationException($"master key {k.KeyId}: keyId does not match the public key");
            pinned.Add(new PinnedKey(k.KeyId, k.Alg, kb));
        }
        if (pinned.Count == 0) throw new InvalidOperationException("server returned no master sign keys");
        if (!Base64Url.TryDecode(er.MasterSealPubKey, out var seal) || seal.Length != 32)
            throw new InvalidOperationException("masterSealPubKey must be 32 bytes");
        return (er, pinned);
    }

    /// <summary>Pins the master keys and stores the device id (wipes previous local state).</summary>
    private static void CommitEnrollment(StateStore store, EnrollResponse er, List<PinnedKey> pinned, Uri baseUri)
    {
        store.WipeAll();
        store.ReplaceMasterKeys(pinned);
        store.SetMeta(StateStore.MetaKeys.MasterSealPubKey, er.MasterSealPubKey);
        store.SetMeta(StateStore.MetaKeys.ServerUrl, baseUri.GetLeftPart(UriPartial.Authority));
        store.SetMeta(StateStore.MetaKeys.EnrolledAt, Time.Utc(DateTimeOffset.UtcNow));
        store.SetMeta(StateStore.MetaKeys.DeviceId, er.DeviceId);
    }

    private static string? ServerErrorCode(string body)
    {
        try { return JsonNode.Parse(body)?["error"]?.GetValue<string>(); }
        catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException) { return null; }
    }

    // ------------------------------------------------------------------------------------------------ connect

    private static int LaunchConnectTool(string? code)
    {
        var exe = Path.Combine(InstallDir, "MinControl.Connect.exe");
        if (!File.Exists(exe)) { Console.Error.WriteLine($"{exe} not found"); return 1; }
        var psi = new System.Diagnostics.ProcessStartInfo(exe) { UseShellExecute = true };
        if (code is not null) psi.ArgumentList.Add(code);
        System.Diagnostics.Process.Start(psi);
        return 0;
    }

    // ------------------------------------------------------------------------------------------------ status (read-only)

    private static int Status(DataPaths paths)
    {
        int problems = 0;
        void Line(string label, string value, bool ok = true)
        {
            if (!ok) problems++;
            Console.WriteLine($"{label,-15}: {value}{(ok ? "" : "   <-- PROBLEM")}");
        }

        var product = SystemTools.InstalledProductCode();
        Line("msi", product is null ? "(not installed via MSI)" : $"{product} v{SystemTools.InstalledVersion(product)}");
        Line("install dir", InstallDir);
        var svc = SystemTools.ServiceState();
        Line("service", svc ?? "NOT INSTALLED", svc == "RUNNING");
        foreach (var mode in SystemTools.SafeBootModes)
            Line($"safeboot {mode.ToLowerInvariant()}", SystemTools.SafeBootRegistered(mode) ? "registered" : "missing", SystemTools.SafeBootRegistered(mode));
        Line("data dir", paths.Root);
        Line("data ACL", paths.IsAclRestricted() ? "SYSTEM+Administrators only" : "NOT RESTRICTED", paths.IsAclRestricted());

        if (File.Exists(AgentConfig.PathIn(paths.Root)))
        {
            var c = AgentConfig.Load(paths.Root);
            Line("config server", c.ServerUrl ?? "(unset)", c.ServerUrl is not null);
            Line("chrome ext", string.IsNullOrEmpty(c.ChromeExtensionId) ? "(none)" : c.ChromeExtensionId!);
            Line("edge ext", string.IsNullOrEmpty(c.EdgeExtensionId) ? "(none)" : c.EdgeExtensionId!);
        }
        else Line("config", "missing (run: MinControl.Setup install --server …)", false);
        var manifest = Path.Combine(InstallDir, "com.mincontrol.nativehost.json");
        Line("native host", File.Exists(manifest) ? manifest : "manifest missing", File.Exists(manifest));

        if (File.Exists(EnrollStatus.PathIn(paths.Root)))
        {
            var last = JsonNode.Parse(File.ReadAllText(EnrollStatus.PathIn(paths.Root)));
            Line("last enrol", $"{(string?)last?["state"]} ({(string?)last?["reason"]}) at {(string?)last?["at"]} {(string?)last?["detail"]}".TrimEnd());
        }
        if (!File.Exists(paths.StateDb)) { Line("enrolment","not enrolled (no state.db)", false); return 1; }
        using var store = new StateStore(paths.StateDb);
        var id = store.GetMeta(StateStore.MetaKeys.DeviceId);
        Line("device id", id ?? "(not enrolled)", id is not null);
        Line("server", store.GetMeta(StateStore.MetaKeys.ServerUrl) ?? "(none)");
        Line("enrolled at", store.GetMeta(StateStore.MetaKeys.EnrolledAt) ?? "-");
        Line("last online", store.GetMeta(StateStore.MetaKeys.LastOnlineUtc) ?? "-");
        Line("device.key", File.Exists(paths.DeviceKey) ? "present" : "MISSING", File.Exists(paths.DeviceKey));
        foreach (var k in store.GetMasterKeys()) Line("master key", $"{k.KeyId} ({k.Alg})");
        var p = store.GetPolicy();
        Line("policy", p is null ? "(none yet)" : $"v{p.Version} seq {p.Seq} stored {p.StoredAt}");
        Line("seq pol/cmd", $"{store.GetSeq("policy")}/{store.GetSeq("command")}");
        Line("outbox", $"{store.OutboxCount} events, {store.OutboxBytes / 1024} KiB");
        return problems == 0 ? 0 : 1;
    }

    // ------------------------------------------------------------------------------------------------ uninstall

    private static async Task<int> UninstallAsync(DataPaths paths, bool purge, bool fromMsi)
    {
        if (!IsElevated()) return RequireElevation();
        int failures = 0;
        void Step(string what, Action action)
        {
            try { action(); Console.WriteLine($"[ok]   {what}"); }
            catch (Exception e) { failures++; Console.Error.WriteLine($"[FAIL] {what}: {e.Message}"); }
        }
        async Task StepAsync(string what, Func<Task> action)
        {
            try { await action(); Console.WriteLine($"[ok]   {what}"); }
            catch (Exception e) { failures++; Console.Error.WriteLine($"[FAIL] {what}: {e.Message}"); }
        }

        // 1. Stop the service first: its watchdog would re-add WFP filters and browser policies.
        Step("stop service", () =>
        {
            if (!SystemTools.StopService(TimeSpan.FromSeconds(45))) throw new InvalidOperationException("service did not stop within 45 s");
        });
        Step("stop helper / native host processes", () => SystemTools.KillAgentProcesses());

        // 2. Remove enforcement (order: network lock first so the managed user gets internet back).
        var config = AgentConfig.Load(paths.Root);   // empty when missing; the native host path still resolves
        await StepAsync("remove WFP filters (NetGuard.RemoveAllAsync)", () => Cleanup.RemoveNetGuardAsync(CancellationToken.None));
        await StepAsync("remove browser policies for all profiles + native host registration", async () =>
        {
            var perSid = await Cleanup.RemoveBrowserPoliciesAsync(config, InstallDir, CancellationToken.None);
            if (perSid.Count > 0) throw new InvalidOperationException(string.Join("; ", perSid));
        });
        Step("remove SafeBoot Minimal/Network keys", SystemTools.RemoveSafeBootKeys);

        // 3. Local state.
        if (purge)
        {
            Step("wipe state.db + device.key", () => Unenroll(paths));
            Step($"delete {paths.Root}", () => { if (Directory.Exists(paths.Root)) Directory.Delete(paths.Root, recursive: true); });
        }
        else Console.WriteLine($"[keep] {paths.Root} (state + device identity; re-install keeps the enrolment; --purge wipes it)");

        // 4. Remove the program itself unless the MSI is already doing that.
        if (!fromMsi)
        {
            if (SystemTools.InstalledProductCode() is { } code)
            {
                Console.WriteLine($"Removing MSI product {code} (msiexec /x) …");
                var (rc, output) = SystemTools.Run(Path.Combine(Environment.SystemDirectory, "msiexec.exe"), "/x", code, "/passive", "/norestart");
                if (rc is not (0 or 3010)) { failures++; Console.Error.WriteLine($"[FAIL] msiexec /x returned {rc} {output}"); }
                else Console.WriteLine("[ok]   MSI removed" + (rc == 3010 ? " (reboot required)" : ""));
            }
            else if (SystemTools.ServiceState() is not null)
            {
                Step("delete service (non-MSI install)", () => { if (!SystemTools.DeleteService()) throw new InvalidOperationException("sc delete failed"); });
            }
        }

        Console.WriteLine(failures == 0 ? "Uninstall cleanup complete. Revoke the device in the master app." : $"Uninstall finished with {failures} failure(s); see above.");
        return failures == 0 ? 0 : 1;
    }

    private static int Unenroll(DataPaths paths)
    {
        if (!IsElevated()) return RequireElevation();
        if (File.Exists(paths.StateDb))
            using (var store = new StateStore(paths.StateDb)) store.WipeAll();
        using (var identity = new DeviceIdentity(paths, new DpapiMachineKeyProtector())) identity.Delete();
        EnrollStatus.Clear(paths, registry: true);
        Console.WriteLine("Local identity and state removed. Revoke the device in the master app as well.");
        return 0;
    }
}
