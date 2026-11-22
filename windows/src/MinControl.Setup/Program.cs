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
//   enroll <code> [--server <https-url>] [--force]          (server defaults to config.json ServerUrl)
//   status                                                   (read-only)
//   uninstall --yes [--purge] [--from-msi]
//       Stops the service, removes WFP filters, browser policies (all profiles) + native host registration,
//       SafeBoot keys. Keeps state.db/device.key unless --purge. Without --from-msi it then removes the MSI
//       product (msiexec /x) or, for a non-MSI install, deletes the service.
//   unenroll --yes                                           (wipes identity + state only)
// Common: [--data-dir <dir>] (tests only; default %ProgramData%\MinControl).
// Exit codes: 0 ok, 1 failure, 2 usage, 3 not elevated.

return await Cli.RunAsync(args);

internal static class Cli
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
                    var server = Opt(args, "--server") ?? (File.Exists(AgentConfig.PathIn(paths.Root)) ? AgentConfig.Load(paths.Root).ServerUrl : null);
                    if (server is null) { Console.Error.WriteLine("no --server given and config.json has no ServerUrl (run install first)"); return 2; }
                    return await EnrollAsync(paths, args[1], server, args.Contains("--force"), args.Contains("--insecure-http"));
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
              MinControl.Setup enroll <CODE> [--server <https://…>] [--force]
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

    private static async Task<int> EnrollAsync(DataPaths paths, string rawCode, string server, bool force, bool allowHttp)
    {
        if (!IsElevated()) return RequireElevation();
        var code = rawCode.Replace("-", "").Trim().ToUpperInvariant();
        if (code.Length != 8 || code.Any(c => !"0123456789ABCDEFGHJKMNPQRSTVWXYZ".Contains(c)))
        { Console.Error.WriteLine("pairing code must be 8 Crockford base32 characters (XXXX-XXXX)"); return 2; }
        if (!Uri.TryCreate(server, UriKind.Absolute, out var baseUri) || !(baseUri.Scheme == "https" || (allowHttp && baseUri.Scheme == "http")))
        { Console.Error.WriteLine("--server must be an absolute https:// URL"); return 2; }

        paths.EnsureExists();
        paths.ApplyRestrictedAcl();   // I7: SYSTEM + Administrators only, before any secret is written

        using var store = new StateStore(paths.StateDb);
        if (store.GetMeta(StateStore.MetaKeys.DeviceId) is { } existing && !force)
        { Console.Error.WriteLine($"already enrolled as {existing}; use --force to re-enrol (wipes local state)"); return 2; }

        var users = LocalUsers.Enumerate();
        Console.WriteLine("Local users:");
        foreach (var u in users) Console.WriteLine($"  {u.Name,-24} {u.Sid}{(u.IsAdmin ? "  (admin - can never be managed)" : "")}");

        using var identity = new DeviceIdentity(paths, new DpapiMachineKeyProtector());
        var pub = identity.CreateNew();
        var osv = Environment.OSVersion.Version;
        var request = new JsonObject
        {
            ["code"] = code,
            ["devicePubKey"] = Base64Url.Encode(pub),
            ["hostname"] = Environment.MachineName,
            ["osVersion"] = $"{osv.Major}.{osv.Minor}.{osv.Build}",
            ["agentVersion"] = AgentVersion,
            ["localUsers"] = new JsonArray(users.Select(u => (JsonNode)new JsonObject { ["sid"] = u.Sid, ["name"] = u.Name, ["isAdmin"] = u.IsAdmin }).ToArray()),
        };

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        using var resp = await http.PostAsync(new Uri(baseUri, "/v1/enroll"), JsonContent.Create(request));
        var text = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode)
        {
            identity.Delete();
            Console.Error.WriteLine($"enrolment failed: HTTP {(int)resp.StatusCode} {text}");
            return 1;
        }
        var er = JsonSerializer.Deserialize<EnrollResponse>(text, ProtocolJson.Options) ?? throw new InvalidOperationException("empty enrol response");
        if (!UlidGenerator.IsValid(er.DeviceId)) throw new InvalidOperationException("server returned an invalid deviceId");

        var pinned = new List<PinnedKey>();
        foreach (var k in er.MasterKeys)
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

        store.WipeAll();
        store.ReplaceMasterKeys(pinned);
        store.SetMeta(StateStore.MetaKeys.MasterSealPubKey, er.MasterSealPubKey);
        store.SetMeta(StateStore.MetaKeys.ServerUrl, baseUri.GetLeftPart(UriPartial.Authority));
        store.SetMeta(StateStore.MetaKeys.EnrolledAt, Time.Utc(DateTimeOffset.UtcNow));
        store.SetMeta(StateStore.MetaKeys.DeviceId, er.DeviceId);

        Console.WriteLine($"Enrolled as {er.DeviceId}. Pinned master keys: {string.Join(", ", pinned.Select(p => $"{p.KeyId} ({p.Alg})"))}");
        Console.WriteLine("Compare the fingerprints with the master app, then choose managed users there.");
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

        if (!File.Exists(paths.StateDb)) { Line("enrolment", "not enrolled (no state.db)", false); return 1; }
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
        Console.WriteLine("Local identity and state removed. Revoke the device in the master app as well.");
        return 0;
    }
}
