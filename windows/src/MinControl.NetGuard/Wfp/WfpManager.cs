using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
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

/// <summary>One filter of our provider as read back from BFE (diagnostics).</summary>
public sealed record WfpInstalledFilter(ulong Id, Guid Key, string? Name, string Layer, string Action, string? Weight,
    string? EffectiveWeight, uint Flags, IReadOnlyList<string> Conditions, string? Sid);

/// <summary>A sublayer registered on the machine (ours and other providers', to spot higher-weight competitors).</summary>
public sealed record WfpSublayerInfo(Guid Key, string? Name, ushort Weight, bool Ours);

/// <summary>Read-back of the WFP state (FwpmFilterEnum0 / FwpmSubLayerEnum0).</summary>
public sealed record WfpSnapshot(bool ProviderPresent, bool SublayerPresent, IReadOnlyList<WfpSublayerInfo> Sublayers,
    IReadOnlyList<WfpInstalledFilter> Filters);

public interface IWfpManager
{
    void Apply(IReadOnlyList<WfpUserRule> rules);
    WfpVerifyResult Verify(IReadOnlyList<WfpUserRule> rules);
    void RemoveAll();
    /// <summary>Enumerates our provider's filters with decoded conditions, and all sublayers.</summary>
    WfpSnapshot Describe();
}

/// <summary>
/// Persistent per-user network lock through the Windows Filtering Platform (user mode, no driver).
/// <para>Provider, sublayer and filters are created with the PERSISTENT flag, so BFE re-loads them at boot before the
/// MinControl service starts — the managed user is offline until the service (proxy) is up (I4). BOOTTIME filters are
/// deliberately not used: they cannot carry ALE user conditions and would block every account.</para>
/// <para>Per SID and per layer (ALE_AUTH_CONNECT_V4/V6, ALE_AUTH_RECV_ACCEPT_V4/V6): permit loopback (weight 15), permit
/// each exempt app (14), hard block everything else (0, CLEAR_ACTION_RIGHT); see <see cref="WfpFilterPlan"/> for the
/// exact conditions (user SD incl. the AppContainer / restricted-token ACEs).</para>
/// Our sublayer has weight 0xFFFE, so it is evaluated before Windows Defender Firewall's and most third-party sublayers;
/// its hard block cannot be overridden by a permit in a lower-weight sublayer.
/// Filter keys are deterministic (hash of revision/sid/layer/kind/app) so <see cref="Verify"/> can diff without state.
/// </summary>
public sealed partial class WfpManager : IWfpManager
{
    public static readonly Guid ProviderKey = new("6d1f3c2a-8b4e-4f7a-9c51-2e8a7d0b4c11");
    public static readonly Guid SublayerKey = new("b3e5a7c9-1d2f-4a6b-8e0c-5f7d9a1b3c22");
    public const ushort SublayerWeight = 0xFFFE;

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
            var perSid = new List<(string Sid, int Filters, int Apps)>();
            foreach (var rule in rules)
            {
                var (n, apps) = AddUserFilters(engine.Handle, rule);
                added += n;
                perSid.Add((rule.Sid, n, apps));
            }
            Check(WfpNative.FwpmTransactionCommit0(engine.Handle), "FwpmTransactionCommit0");
            foreach (var (sid, n, apps) in perSid)
                _log.LogInformation("WFP applied for {Sid}: {Filters} filters, {Apps} exempt app(s), plan {Rev}", sid, n, apps, WfpFilterPlan.Revision);
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

    public WfpSnapshot Describe()
    {
        using var engine = Engine.Open();
        var providerPresent = Exists(WfpNative.FwpmProviderGetByKey0(engine.Handle, ProviderKey, out var p), ref p);
        var sublayerPresent = Exists(WfpNative.FwpmSubLayerGetByKey0(engine.Handle, SublayerKey, out var s), ref s);
        var filters = new List<WfpInstalledFilter>();
        EnumerateFilters(engine.Handle, f => { if (IsOurs(f)) filters.Add(DescribeFilter(f)); });
        return new WfpSnapshot(providerPresent, sublayerPresent, EnumerateSublayers(engine.Handle), filters);
    }

    /// <summary>Deterministic filter keys for one user (exposed for tests/diagnostics).</summary>
    public static IEnumerable<Guid> ExpectedKeys(WfpUserRule rule) => WfpFilterPlan.Build(rule).Select(f => f.Key);

    public static Guid FilterKey(string sid, Guid layer, string kind, string? app) => WfpFilterPlan.FilterKey(sid, layer, kind, app);

    /// <summary>"S-1-5-21-…" of the first ACE in an SDDL string, or null.</summary>
    internal static string? FirstAceSid(string sddl)
    {
        var m = FirstAceRegex().Match(sddl);
        return m.Success ? m.Groups[1].Value : null;
    }

    [GeneratedRegex(@"\(A;;[^;]*;;;(S-1-[0-9-]+)\)", RegexOptions.CultureInvariant)]
    private static partial Regex FirstAceRegex();

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

    private (int Filters, int Apps) AddUserFilters(IntPtr h, WfpUserRule rule)
    {
        using var mem = new NativeArena();
        var userSd = mem.UserSecurityDescriptor(rule.Sid);   // FWP_BYTE_BLOB* holding a self-relative SD
        var appIds = new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in rule.ExemptAppPaths)
        {
            var rc = WfpNative.FwpmGetAppIdFromFileName0(path, out var blob);
            if (rc != 0) { _log.LogWarning("Exempt app {Path} skipped: FwpmGetAppIdFromFileName0 0x{Rc:X8}", path, rc); continue; }
            mem.TrackFwpMemory(blob);
            appIds[path] = blob;
        }

        var count = 0;
        foreach (var spec in WfpFilterPlan.Build(rule, appIds.Keys))
        {
            var conditions = spec.Conditions.Select(c => ToNative(c, userSd, appIds)).ToArray();
            AddFilter(h, mem, spec.Key, spec.Layer, $"MinControl {spec.Kind} {spec.LayerName}", spec.Action, spec.Weight, spec.Flags, conditions);
            count++;
        }
        return (count, appIds.Count);
    }

    private static FWPM_FILTER_CONDITION0 ToNative(WfpConditionSpec c, IntPtr userSd, IReadOnlyDictionary<string, IntPtr> appIds)
    {
        var value = c.ValueType switch
        {
            FwpConst.FWP_SECURITY_DESCRIPTOR_TYPE => new FWP_VALUE0 { type = c.ValueType, ptr = userSd },
            FwpConst.FWP_BYTE_BLOB_TYPE => new FWP_VALUE0 { type = c.ValueType, ptr = appIds[c.Value] },
            FwpConst.FWP_UINT32 => new FWP_VALUE0 { type = c.ValueType, uint64 = uint.Parse(c.Value, CultureInfo.InvariantCulture) },
            _ => throw new InvalidOperationException($"unsupported condition value type {c.ValueType}"),
        };
        return new FWPM_FILTER_CONDITION0 { fieldKey = c.FieldKey, matchType = c.MatchType, conditionValue = value };
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
        EnumerateFilters(h, f => { if (IsOurs(f)) result.Add((f.filterId, f.filterKey)); });
        return result;
    }

    private static bool IsOurs(in FWPM_FILTER0 f) =>
        f.providerKey != IntPtr.Zero && Marshal.PtrToStructure<Guid>(f.providerKey) == ProviderKey;

    /// <summary>Visits every filter; the struct's pointers are valid only during the callback.</summary>
    private static void EnumerateFilters(IntPtr h, Action<FWPM_FILTER0> visit)
    {
        Check(WfpNative.FwpmFilterCreateEnumHandle0(h, IntPtr.Zero, out var enumHandle), "FwpmFilterCreateEnumHandle0");
        try
        {
            while (true)
            {
                Check(WfpNative.FwpmFilterEnum0(h, enumHandle, 512, out var entries, out var n), "FwpmFilterEnum0");
                try
                {
                    for (var i = 0; i < n; i++)
                        visit(Marshal.PtrToStructure<FWPM_FILTER0>(Marshal.ReadIntPtr(entries, i * IntPtr.Size)));
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
    }

    private static List<WfpSublayerInfo> EnumerateSublayers(IntPtr h)
    {
        var result = new List<WfpSublayerInfo>();
        Check(WfpNative.FwpmSubLayerCreateEnumHandle0(h, IntPtr.Zero, out var enumHandle), "FwpmSubLayerCreateEnumHandle0");
        try
        {
            while (true)
            {
                Check(WfpNative.FwpmSubLayerEnum0(h, enumHandle, 256, out var entries, out var n), "FwpmSubLayerEnum0");
                try
                {
                    for (var i = 0; i < n; i++)
                    {
                        var sl = Marshal.PtrToStructure<FWPM_SUBLAYER0>(Marshal.ReadIntPtr(entries, i * IntPtr.Size));
                        result.Add(new WfpSublayerInfo(sl.subLayerKey, Str(sl.displayData.name), sl.weight, sl.subLayerKey == SublayerKey));
                    }
                }
                finally
                {
                    if (entries != IntPtr.Zero) WfpNative.FwpmFreeMemory0(ref entries);
                }
                if (n < 256) break;
            }
        }
        finally
        {
            WfpNative.FwpmSubLayerDestroyEnumHandle0(h, enumHandle);
        }
        return result.OrderByDescending(x => x.Weight).ToList();
    }

    private static WfpInstalledFilter DescribeFilter(FWPM_FILTER0 f)
    {
        var conditions = new List<string>();
        string? sid = null;
        var size = Marshal.SizeOf<FWPM_FILTER_CONDITION0>();
        for (var i = 0; i < f.numFilterConditions && f.filterCondition != IntPtr.Zero; i++)
        {
            var c = Marshal.PtrToStructure<FWPM_FILTER_CONDITION0>(f.filterCondition + i * size);
            var value = DecodeValue(c.conditionValue);
            if (c.fieldKey == FwpGuids.ConditionAleUserId) sid ??= FirstAceSid(value);
            conditions.Add($"{WfpFilterPlan.FieldName(c.fieldKey)} {MatchName(c.matchType)} {value}");
        }
        return new WfpInstalledFilter(f.filterId, f.filterKey, Str(f.displayData.name), WfpFilterPlan.LayerName(f.layerKey),
            WfpFilterPlan.ActionName(f.action.type), DecodeValue(f.weight), DecodeValue(f.effectiveWeight), f.flags, conditions, sid);
    }

    private static string MatchName(uint m) => m switch
    {
        FwpConst.FWP_MATCH_EQUAL => "==",
        FwpConst.FWP_MATCH_FLAGS_ALL_SET => "all-set",
        _ => $"match#{m}",
    };

    private static string DecodeValue(FWP_VALUE0 v)
    {
        switch (v.type)
        {
            case FwpConst.FWP_EMPTY: return "empty";
            case FwpConst.FWP_UINT8: return ((byte)v.uint64).ToString(CultureInfo.InvariantCulture);
            case FwpConst.FWP_UINT16: return ((ushort)v.uint64).ToString(CultureInfo.InvariantCulture);
            case FwpConst.FWP_UINT32: return $"0x{(uint)v.uint64:X}";
            case FwpConst.FWP_UINT64:   // FWP_VALUE0.uint64 is a UINT64* in the union
                return v.ptr == IntPtr.Zero ? "null" : ((ulong)Marshal.ReadInt64(v.ptr)).ToString(CultureInfo.InvariantCulture);
            case FwpConst.FWP_BYTE_BLOB_TYPE:
            {
                if (v.ptr == IntPtr.Zero) return "null";
                var blob = Marshal.PtrToStructure<FWP_BYTE_BLOB>(v.ptr);
                if (blob.data == IntPtr.Zero || blob.size < 2) return "blob";
                return (Marshal.PtrToStringUni(blob.data, (int)(blob.size / 2)) ?? "").TrimEnd('\0');
            }
            case FwpConst.FWP_SECURITY_DESCRIPTOR_TYPE:
            {
                if (v.ptr == IntPtr.Zero) return "null";
                var blob = Marshal.PtrToStructure<FWP_BYTE_BLOB>(v.ptr);
                if (blob.data == IntPtr.Zero) return "sd:null";
                if (!WfpNative.ConvertSecurityDescriptorToStringSecurityDescriptor(blob.data, 1,
                        WfpNative.OWNER_SECURITY_INFORMATION | WfpNative.GROUP_SECURITY_INFORMATION | WfpNative.DACL_SECURITY_INFORMATION,
                        out var sddl, out _))
                    return $"sd:error {Marshal.GetLastPInvokeError()}";
                try { return Marshal.PtrToStringUni(sddl) ?? ""; }
                finally { WfpNative.LocalFree(sddl); }
            }
            default: return $"type#{v.type}";
        }
    }

    private static string? Str(IntPtr p) => p == IntPtr.Zero ? null : Marshal.PtrToStringUni(p);

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

        /// <summary>FWP_BYTE_BLOB* wrapping the self-relative SD of <see cref="WfpFilterPlan.UserSddl"/>.</summary>
        public IntPtr UserSecurityDescriptor(string sid)
        {
            if (!WfpNative.ConvertStringSecurityDescriptorToSecurityDescriptor(WfpFilterPlan.UserSddl(sid), 1, out var sd, out var size))
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
