using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MinControl.NetGuard.Wfp;

/// <summary>Desired WFP state for one managed (never admin) SID.</summary>
public sealed record WfpUserRule(string Sid, IReadOnlyList<string> ExemptAppPaths);

/// <summary>Result of comparing installed filters with the desired set.</summary>
public sealed record WfpVerifyResult(bool ProviderPresent, bool SublayerPresent, IReadOnlyCollection<Guid> MissingFilterKeys, int UnexpectedFilters)
{
    public bool Ok => ProviderPresent && SublayerPresent && MissingFilterKeys.Count == 0;
}

public interface IWfpManager
{
    void Apply(IReadOnlyList<WfpUserRule> rules);
    WfpVerifyResult Verify(IReadOnlyList<WfpUserRule> rules);
    void RemoveAll();
}

/// <summary>
/// Persistent per-user network lock through the Windows Filtering Platform (user mode, no driver).
/// <para>Provider, sublayer and filters are created with the PERSISTENT flag, so BFE re-loads them at boot before the
/// MinControl service starts — the managed user is offline until the service (proxy) is up (I4). BOOTTIME filters are
/// deliberately not used: they cannot carry ALE user conditions and would block every account.</para>
/// <para>Per SID and per layer (ALE_AUTH_CONNECT_V4/V6, ALE_AUTH_RECV_ACCEPT_V4/V6):
/// permit loopback (weight 15), permit each exempt app (14), hard block everything else (0, CLEAR_ACTION_RIGHT).
/// The user condition is FWPM_CONDITION_ALE_USER_ID with an SD "D:(A;;CC;;;SID)" (CC = FWP_ACTRL_MATCH_FILTER).</para>
/// Filter keys are deterministic (hash of sid/layer/kind/app) so <see cref="Verify"/> can diff without state.
/// </summary>
public sealed class WfpManager : IWfpManager
{
    public static readonly Guid ProviderKey = new("6d1f3c2a-8b4e-4f7a-9c51-2e8a7d0b4c11");
    public static readonly Guid SublayerKey = new("b3e5a7c9-1d2f-4a6b-8e0c-5f7d9a1b3c22");
    private const ushort SublayerWeight = 0xFFFE;
    private const byte WeightPermitLoopback = 15, WeightPermitApp = 14, WeightBlock = 0;

    private static readonly (Guid Layer, string Name)[] Layers =
    [
        (FwpGuids.LayerAleAuthConnectV4, "connect-v4"),
        (FwpGuids.LayerAleAuthConnectV6, "connect-v6"),
        (FwpGuids.LayerAleAuthRecvAcceptV4, "accept-v4"),
        (FwpGuids.LayerAleAuthRecvAcceptV6, "accept-v6"),
    ];

    private readonly ILogger _log;

    public WfpManager(ILogger<WfpManager>? log = null) => _log = (ILogger?)log ?? NullLogger.Instance;

    // ------------------------------------------------------------------ public API

    /// <summary>Idempotent: in one transaction delete all our filters and add the desired ones. On failure nothing changes.</summary>
    public void Apply(IReadOnlyList<WfpUserRule> rules)
    {
        using var engine = Engine.Open();
        Check(WfpNative.FwpmTransactionBegin0(engine.Handle, 0), "FwpmTransactionBegin0");
        try
        {
            EnsureProviderAndSublayer(engine.Handle);
            foreach (var f in EnumerateOurFilters(engine.Handle))
                Check(WfpNative.FwpmFilterDeleteById0(engine.Handle, f.Id), "FwpmFilterDeleteById0", FwpConst.FWP_E_FILTER_NOT_FOUND);
            var added = 0;
            foreach (var rule in rules)
                added += AddUserFilters(engine.Handle, rule);
            Check(WfpNative.FwpmTransactionCommit0(engine.Handle), "FwpmTransactionCommit0");
            _log.LogInformation("WFP applied: {Users} users, {Filters} filters", rules.Count, added);
        }
        catch
        {
            WfpNative.FwpmTransactionAbort0(engine.Handle);
            throw;
        }
    }

    public WfpVerifyResult Verify(IReadOnlyList<WfpUserRule> rules)
    {
        using var engine = Engine.Open();
        var providerPresent = Exists(WfpNative.FwpmProviderGetByKey0(engine.Handle, ProviderKey, out var p), ref p);
        var sublayerPresent = Exists(WfpNative.FwpmSubLayerGetByKey0(engine.Handle, SublayerKey, out var s), ref s);
        var installed = EnumerateOurFilters(engine.Handle).Select(f => f.Key).ToHashSet();
        var expected = rules.SelectMany(ExpectedKeys).ToHashSet();
        var missing = expected.Where(k => !installed.Contains(k)).ToList();
        var unexpected = installed.Count(k => !expected.Contains(k));
        return new WfpVerifyResult(providerPresent, sublayerPresent, missing, unexpected);
    }

    /// <summary>Uninstall: removes all our filters, the sublayer and the provider.</summary>
    public void RemoveAll()
    {
        using var engine = Engine.Open();
        Check(WfpNative.FwpmTransactionBegin0(engine.Handle, 0), "FwpmTransactionBegin0");
        try
        {
            foreach (var f in EnumerateOurFilters(engine.Handle))
                Check(WfpNative.FwpmFilterDeleteById0(engine.Handle, f.Id), "FwpmFilterDeleteById0", FwpConst.FWP_E_FILTER_NOT_FOUND);
            Check(WfpNative.FwpmSubLayerDeleteByKey0(engine.Handle, SublayerKey), "FwpmSubLayerDeleteByKey0", FwpConst.FWP_E_SUBLAYER_NOT_FOUND);
            Check(WfpNative.FwpmProviderDeleteByKey0(engine.Handle, ProviderKey), "FwpmProviderDeleteByKey0", FwpConst.FWP_E_PROVIDER_NOT_FOUND);
            Check(WfpNative.FwpmTransactionCommit0(engine.Handle), "FwpmTransactionCommit0");
            _log.LogInformation("WFP provider, sublayer and filters removed");
        }
        catch
        {
            WfpNative.FwpmTransactionAbort0(engine.Handle);
            throw;
        }
    }

    /// <summary>Deterministic filter keys for one user (exposed for tests/diagnostics).</summary>
    public static IEnumerable<Guid> ExpectedKeys(WfpUserRule rule)
    {
        foreach (var (layer, _) in Layers)
        {
            yield return FilterKey(rule.Sid, layer, "loopback", null);
            foreach (var app in rule.ExemptAppPaths) yield return FilterKey(rule.Sid, layer, "app", app);
            yield return FilterKey(rule.Sid, layer, "block", null);
        }
    }

    public static Guid FilterKey(string sid, Guid layer, string kind, string? app)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"mincontrol/wfp/{sid.ToUpperInvariant()}/{layer:N}/{kind}/{app?.ToUpperInvariant()}"));
        var g = bytes.AsSpan(0, 16).ToArray();
        g[7] = (byte)((g[7] & 0x0F) | 0x50);   // version 5-style
        g[8] = (byte)((g[8] & 0x3F) | 0x80);   // RFC 4122 variant
        return new Guid(g);
    }

    // ------------------------------------------------------------------ internals

    private void EnsureProviderAndSublayer(IntPtr h)
    {
        using var mem = new NativeArena();
        var provider = new FWPM_PROVIDER0
        {
            providerKey = ProviderKey,
            displayData = new FWPM_DISPLAY_DATA0 { name = mem.Str("MinControl"), description = mem.Str("MinControl per-user network guard") },
            flags = FwpConst.FWPM_PROVIDER_FLAG_PERSISTENT,
        };
        Check(WfpNative.FwpmProviderAdd0(h, provider, IntPtr.Zero), "FwpmProviderAdd0", FwpConst.FWP_E_ALREADY_EXISTS);

        var sublayer = new FWPM_SUBLAYER0
        {
            subLayerKey = SublayerKey,
            displayData = new FWPM_DISPLAY_DATA0 { name = mem.Str("MinControl sublayer"), description = mem.Str("MinControl per-user network guard") },
            flags = FwpConst.FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey = mem.Guid(ProviderKey),
            weight = SublayerWeight,
        };
        Check(WfpNative.FwpmSubLayerAdd0(h, sublayer, IntPtr.Zero), "FwpmSubLayerAdd0", FwpConst.FWP_E_ALREADY_EXISTS);
    }

    private int AddUserFilters(IntPtr h, WfpUserRule rule)
    {
        using var mem = new NativeArena();
        var userSd = mem.UserSecurityDescriptor(rule.Sid);   // FWP_BYTE_BLOB* holding a self-relative SD
        var appIds = new List<(string Path, IntPtr Blob)>();
        foreach (var path in rule.ExemptAppPaths)
        {
            var rc = WfpNative.FwpmGetAppIdFromFileName0(path, out var blob);
            if (rc != 0) { _log.LogWarning("Exempt app {Path} skipped: FwpmGetAppIdFromFileName0 0x{Rc:X8}", path, rc); continue; }
            mem.TrackFwpMemory(blob);
            appIds.Add((path, blob));
        }

        var count = 0;
        foreach (var (layer, layerName) in Layers)
        {
            var userCond = new FWPM_FILTER_CONDITION0
            {
                fieldKey = FwpGuids.ConditionAleUserId,
                matchType = FwpConst.FWP_MATCH_EQUAL,
                conditionValue = new FWP_VALUE0 { type = FwpConst.FWP_SECURITY_DESCRIPTOR_TYPE, ptr = userSd },
            };

            // 1. permit loopback (the proxy lives there)
            var loopCond = new FWPM_FILTER_CONDITION0
            {
                fieldKey = FwpGuids.ConditionFlags,
                matchType = FwpConst.FWP_MATCH_FLAGS_ALL_SET,
                conditionValue = new FWP_VALUE0 { type = FwpConst.FWP_UINT32, uint64 = FwpConst.FWP_CONDITION_FLAG_IS_LOOPBACK },
            };
            AddFilter(h, mem, FilterKey(rule.Sid, layer, "loopback", null), layer, $"MinControl permit loopback {layerName}",
                FwpConst.FWP_ACTION_PERMIT, WeightPermitLoopback, FwpConst.FWPM_FILTER_FLAG_PERSISTENT, [userCond, loopCond]);
            count++;

            // 2. permit exempt apps
            foreach (var (path, blob) in appIds)
            {
                var appCond = new FWPM_FILTER_CONDITION0
                {
                    fieldKey = FwpGuids.ConditionAleAppId,
                    matchType = FwpConst.FWP_MATCH_EQUAL,
                    conditionValue = new FWP_VALUE0 { type = FwpConst.FWP_BYTE_BLOB_TYPE, ptr = blob },
                };
                AddFilter(h, mem, FilterKey(rule.Sid, layer, "app", path), layer, $"MinControl permit app {layerName}",
                    FwpConst.FWP_ACTION_PERMIT, WeightPermitApp, FwpConst.FWPM_FILTER_FLAG_PERSISTENT, [userCond, appCond]);
                count++;
            }

            // 3. hard block everything else (all protocols: TCP, UDP/QUIC, DoT, raw)
            AddFilter(h, mem, FilterKey(rule.Sid, layer, "block", null), layer, $"MinControl block {layerName}",
                FwpConst.FWP_ACTION_BLOCK, WeightBlock,
                FwpConst.FWPM_FILTER_FLAG_PERSISTENT | FwpConst.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, [userCond]);
            count++;
        }
        return count;
    }

    private static void AddFilter(IntPtr h, NativeArena mem, Guid key, Guid layer, string name, uint action, byte weight, uint flags,
        FWPM_FILTER_CONDITION0[] conditions)
    {
        var condPtr = mem.Array(conditions);
        var filter = new FWPM_FILTER0
        {
            filterKey = key,
            displayData = new FWPM_DISPLAY_DATA0 { name = mem.Str(name), description = mem.Str("MinControl managed-user network lock") },
            flags = flags,
            providerKey = mem.Guid(ProviderKey),
            layerKey = layer,
            subLayerKey = SublayerKey,
            weight = new FWP_VALUE0 { type = FwpConst.FWP_UINT8, uint64 = weight },
            numFilterConditions = (uint)conditions.Length,
            filterCondition = condPtr,
            action = new FWPM_ACTION0 { type = action },
        };
        Check(WfpNative.FwpmFilterAdd0(h, filter, IntPtr.Zero, out _), "FwpmFilterAdd0");
    }

    private static List<(ulong Id, Guid Key)> EnumerateOurFilters(IntPtr h)
    {
        var result = new List<(ulong, Guid)>();
        Check(WfpNative.FwpmFilterCreateEnumHandle0(h, IntPtr.Zero, out var enumHandle), "FwpmFilterCreateEnumHandle0");
        try
        {
            while (true)
            {
                Check(WfpNative.FwpmFilterEnum0(h, enumHandle, 512, out var entries, out var n), "FwpmFilterEnum0");
                try
                {
                    for (var i = 0; i < n; i++)
                    {
                        var fp = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                        var f = Marshal.PtrToStructure<FWPM_FILTER0>(fp);
                        if (f.providerKey != IntPtr.Zero && Marshal.PtrToStructure<Guid>(f.providerKey) == ProviderKey)
                            result.Add((f.filterId, f.filterKey));
                    }
                }
                finally
                {
                    if (entries != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref entries);
                }
                if (n < 512) break;
            }
        }
        finally
        {
            WfpNative.FwpmFilterDestroyEnumHandle0(h, enumHandle);
        }
        return result;
    }

    private static bool Exists(uint rc, ref IntPtr obj)
    {
        if (obj != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref obj);
        if (rc == 0) return true;
        if (rc is FwpConst.FWP_E_PROVIDER_NOT_FOUND or FwpConst.FWP_E_SUBLAYER_NOT_FOUND or FwpConst.FWP_E_NOT_FOUND) return false;
        throw new WfpException("Get", rc);
    }

    private static void Check(uint rc, string op, uint tolerated = 0)
    {
        if (rc == 0 || (tolerated != 0 && rc == tolerated)) return;
        throw new WfpException(op, rc);
    }

    private sealed class Engine : IDisposable
    {
        public IntPtr Handle { get; private init; }

        public static Engine Open()
        {
            // Non-dynamic session (session = NULL): required for persistent objects.
            Check(WfpNative.FwpmEngineOpen0(IntPtr.Zero, FwpConst.RPC_C_AUTHN_WINNT, IntPtr.Zero, IntPtr.Zero, out var h), "FwpmEngineOpen0");
            return new Engine { Handle = h };
        }

        public void Dispose()
        {
            if (Handle != IntPtr.Zero) WfpNative.FwpmEngineClose0(Handle);
        }
    }

    /// <summary>Tracks unmanaged allocations for one WFP call sequence.</summary>
    private sealed class NativeArena : IDisposable
    {
        private readonly List<IntPtr> _hglobal = [];
        private readonly List<IntPtr> _local = [];
        private readonly List<IntPtr> _fwp = [];

        public IntPtr Str(string s) { var p = Marshal.StringToHGlobalUni(s); _hglobal.Add(p); return p; }

        public IntPtr Guid(Guid g) { var p = Alloc(16); Marshal.StructureToPtr(g, p, false); return p; }

        public IntPtr Array<T>(T[] items) where T : struct
        {
            var size = Marshal.SizeOf<T>();
            var p = Alloc(size * items.Length);
            for (var i = 0; i < items.Length; i++) Marshal.StructureToPtr(items[i], p + i * size, false);
            return p;
        }

        /// <summary>FWP_BYTE_BLOB* wrapping a self-relative SD that grants FWP_ACTRL_MATCH_FILTER (CC) to the SID.</summary>
        public IntPtr UserSecurityDescriptor(string sid)
        {
            if (!sid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase) || sid.Any(c => !(char.IsAsciiDigit(c) || c is '-' or 'S' or 's')))
                throw new ArgumentException("invalid SID", nameof(sid));
            if (!WfpNative.ConvertStringSecurityDescriptorToSecurityDescriptor($"D:(A;;CC;;;{sid})", 1, out var sd, out var size))
                throw new WfpException("ConvertStringSecurityDescriptorToSecurityDescriptorW", (uint)Marshal.GetLastPInvokeError());
            _local.Add(sd);
            var blob = Alloc(Marshal.SizeOf<FWP_BYTE_BLOB>());
            Marshal.StructureToPtr(new FWP_BYTE_BLOB { size = size, data = sd }, blob, false);
            return blob;
        }

        public void TrackFwpMemory(IntPtr p) => _fwp.Add(p);

        private IntPtr Alloc(int size)
        {
            var p = Marshal.AllocHGlobal(Math.Max(1, size));
            _hglobal.Add(p);
            return p;
        }

        public void Dispose()
        {
            foreach (var p in _hglobal) Marshal.FreeHGlobal(p);
            foreach (var p in _local) WfpNative.LocalFree(p);
            for (var i = 0; i < _fwp.Count; i++) { var p = _fwp[i]; WfpNative.FwpmFreeMemory0(ref p); }
        }
    }
}
