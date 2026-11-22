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

// MinControl.Setup — run elevated.
//   enroll <code> --server <https-url> [--force] [--data-dir <dir>]
//   status [--data-dir <dir>]
//   unenroll --yes [--data-dir <dir>]
//   install-service --exe <path to MinControl.Service.exe> --confirm
//       Registers the Windows service via sc.exe (LocalSystem, auto start, restart on failure).
//       Service installation belongs to win-session; this verb exists for the installer and is never run by tests.

return await Cli.RunAsync(args);

internal static class Cli
{
    private static readonly string AgentVersion =
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";

    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0) return Usage();
        var dataDir = Opt(args, "--data-dir");
        var paths = new DataPaths(dataDir);
        try
        {
            switch (args[0])
            {
                case "enroll":
                    if (args.Length < 2 || Opt(args, "--server") is not { } server) return Usage();
                    return await EnrollAsync(paths, args[1], server, args.Contains("--force"), args.Contains("--insecure-http"));
                case "status":
                    return Status(paths);
                case "unenroll":
                    if (!args.Contains("--yes")) { Console.Error.WriteLine("unenroll wipes the device identity and state; pass --yes"); return 2; }
                    return Unenroll(paths);
                case "install-service":
                    return InstallService(Opt(args, "--exe"), args.Contains("--confirm"));
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
              MinControl.Setup enroll <CODE> --server <https://…> [--force]
              MinControl.Setup status
              MinControl.Setup unenroll --yes
              MinControl.Setup install-service --exe <MinControl.Service.exe> --confirm
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
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static int RequireElevation()
    {
        Console.Error.WriteLine("run this command from an elevated (Administrator) prompt");
        return 3;
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

    // ------------------------------------------------------------------------------------------------ status / unenroll

    private static int Status(DataPaths paths)
    {
        if (!File.Exists(paths.StateDb)) { Console.WriteLine("not enrolled (no state.db)"); return 1; }
        using var store = new StateStore(paths.StateDb);
        var id = store.GetMeta(StateStore.MetaKeys.DeviceId);
        Console.WriteLine($"device id      : {id ?? "(not enrolled)"}");
        Console.WriteLine($"server         : {store.GetMeta(StateStore.MetaKeys.ServerUrl)}");
        Console.WriteLine($"enrolled at    : {store.GetMeta(StateStore.MetaKeys.EnrolledAt)}");
        Console.WriteLine($"last online    : {store.GetMeta(StateStore.MetaKeys.LastOnlineUtc)}");
        Console.WriteLine($"device.key     : {(File.Exists(paths.DeviceKey) ? "present" : "MISSING")}");
        foreach (var k in store.GetMasterKeys()) Console.WriteLine($"master key     : {k.KeyId} ({k.Alg})");
        var p = store.GetPolicy();
        Console.WriteLine($"policy         : {(p is null ? "(none)" : $"v{p.Version} seq {p.Seq} stored {p.StoredAt}")}");
        Console.WriteLine($"seq policy/cmd : {store.GetSeq("policy")}/{store.GetSeq("command")}");
        Console.WriteLine($"outbox         : {store.OutboxCount} events, {store.OutboxBytes / 1024} KiB");
        Console.WriteLine($"ACL restricted : {paths.IsAclRestricted()}");
        return id is null ? 1 : 0;
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

    // ------------------------------------------------------------------------------------------------ install-service (documented; not run in dev)

    private static int InstallService(string? exe, bool confirm)
    {
        if (exe is null || !File.Exists(exe)) { Console.Error.WriteLine("--exe must point to MinControl.Service.exe"); return 2; }
        string[][] commands =
        [
            ["create", "MinControl", "binPath=", $"\"{Path.GetFullPath(exe)}\"", "start=", "auto", "obj=", "LocalSystem", "DisplayName=", "MinControl Agent"],
            ["failure", "MinControl", "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/30000"],
            ["sidtype", "MinControl", "unrestricted"],
        ];
        if (!confirm)
        {
            Console.WriteLine("Would run (pass --confirm to execute):");
            foreach (var c in commands) Console.WriteLine("  sc.exe " + string.Join(' ', c));
            return 0;
        }
        if (!IsElevated()) return RequireElevation();
        foreach (var c in commands)
        {
            var psi = new System.Diagnostics.ProcessStartInfo("sc.exe") { UseShellExecute = false };
            foreach (var a in c) psi.ArgumentList.Add(a);
            using var proc = System.Diagnostics.Process.Start(psi)!;
            proc.WaitForExit();
            if (proc.ExitCode != 0) { Console.Error.WriteLine($"sc.exe {c[0]} failed ({proc.ExitCode})"); return 1; }
        }
        return 0;
    }
}
