namespace MinControl.NetGuard.Wfp;

/// <summary>One condition of a planned filter, as data (tests and diagnostics read it; <see cref="WfpManager"/> marshals it).</summary>
/// <param name="Value">SDDL for the user condition, flag value for the loopback condition, exe path for the app condition.</param>
public sealed record WfpConditionSpec(Guid FieldKey, string Field, uint MatchType, uint ValueType, string Value);

/// <summary>One planned WFP filter for one managed SID.</summary>
/// <param name="Kind"><c>loopback</c> | <c>app</c> | <c>block</c>.</param>
public sealed record WfpFilterSpec(
    Guid Key, Guid Layer, string LayerName, string Kind, string? AppPath, uint Action, byte Weight, uint Flags,
    IReadOnlyList<WfpConditionSpec> Conditions)
{
    public bool IsBlock => Action == FwpConst.FWP_ACTION_BLOCK;
}

/// <summary>
/// Pure builder of the per-SID filter set (no P/Invoke). Per layer (ALE_AUTH_CONNECT_V4/V6, ALE_AUTH_RECV_ACCEPT_V4/V6):
/// <list type="number">
/// <item>PERMIT loopback (weight 15): user SD + FWP_CONDITION_FLAG_IS_LOOPBACK — the only non-exempt permit (the proxy is there);</item>
/// <item>PERMIT each exempt app (weight 14): user SD + ALE_APP_ID;</item>
/// <item>BLOCK everything else (weight 0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT so a permit in a lower-weight sublayer — e.g.
///   Windows Defender Firewall's — cannot override it): user SD only, i.e. every protocol (TCP, UDP/QUIC, DoT, raw).</item>
/// </list>
/// <para><b>User condition.</b> FWPM_CONDITION_ALE_USER_ID, FWP_MATCH_EQUAL, FWP_SECURITY_DESCRIPTOR_TYPE: BFE runs an
/// access check of the connecting token against this SD and the condition matches when FWP_ACTRL_MATCH_FILTER (0x1, SDDL
/// "CC") is granted. That access check is a full one: for an <i>AppContainer / LPAC</i> token (Edge/WebView2/Chrome
/// network-service sandbox, UWP apps) a second pass requires the package SID / capabilities (ALL APPLICATION PACKAGES
/// <c>AC</c> or ALL RESTRICTED APPLICATION PACKAGES <c>S-1-15-2-2</c>) to be granted too, and for a <i>restricted</i> or
/// <i>write-restricted</i> token (Chromium sandbox) a pass over the restricting SIDs (<c>RC</c> = S-1-5-12,
/// <c>WR</c> = S-1-5-33). An SD that grants only the user SID therefore does NOT match those processes and their traffic
/// skipped the block filter. The extra ACEs never widen the match to other accounts: the first pass still needs the
/// managed user's SID in the token, and no normal token carries AC / S-1-15-2-2 / RC / WR as an enabled group.</para>
/// </summary>
public static class WfpFilterPlan
{
    /// <summary>Bumped when the filter content changes so <see cref="WfpManager.Verify"/> sees old filters as stale.</summary>
    public const string Revision = "v2";

    public const byte WeightPermitLoopback = 15, WeightPermitApp = 14, WeightBlock = 0;

    public static readonly IReadOnlyList<(Guid Layer, string Name)> Layers =
    [
        (FwpGuids.LayerAleAuthConnectV4, "connect-v4"),
        (FwpGuids.LayerAleAuthConnectV6, "connect-v6"),
        (FwpGuids.LayerAleAuthRecvAcceptV4, "accept-v4"),
        (FwpGuids.LayerAleAuthRecvAcceptV6, "accept-v6"),
    ];

    /// <summary>Self-relative SD of the user condition. O/G = SYSTEM so the SD is complete for any access-check path.</summary>
    public static string UserSddl(string sid)
    {
        ValidateSid(sid);
        return $"O:SYG:SYD:(A;;CC;;;{sid})(A;;CC;;;AC)(A;;CC;;;S-1-15-2-2)(A;;CC;;;RC)(A;;CC;;;WR)";
    }

    public static void ValidateSid(string sid)
    {
        if (string.IsNullOrEmpty(sid) || !sid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase) ||
            sid.Any(c => !(char.IsAsciiDigit(c) || c is '-' or 'S' or 's')))
            throw new ArgumentException("invalid SID", nameof(sid));
    }

    /// <summary>All filters for <paramref name="rule"/>. <paramref name="usableApps"/> = exempt paths that resolved to a
    /// WFP app id (null = all of <see cref="WfpUserRule.ExemptAppPaths"/>).</summary>
    public static IReadOnlyList<WfpFilterSpec> Build(WfpUserRule rule, IReadOnlyCollection<string>? usableApps = null)
    {
        var sddl = UserSddl(rule.Sid);
        var user = new WfpConditionSpec(FwpGuids.ConditionAleUserId, "ALE_USER_ID", FwpConst.FWP_MATCH_EQUAL,
            FwpConst.FWP_SECURITY_DESCRIPTOR_TYPE, sddl);
        var loop = new WfpConditionSpec(FwpGuids.ConditionFlags, "FLAGS", FwpConst.FWP_MATCH_FLAGS_ALL_SET,
            FwpConst.FWP_UINT32, FwpConst.FWP_CONDITION_FLAG_IS_LOOPBACK.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var apps = rule.ExemptAppPaths.Where(a => usableApps is null || usableApps.Contains(a)).ToList();

        var list = new List<WfpFilterSpec>();
        foreach (var (layer, name) in Layers)
        {
            list.Add(new WfpFilterSpec(FilterKey(rule.Sid, layer, "loopback", null), layer, name, "loopback", null,
                FwpConst.FWP_ACTION_PERMIT, WeightPermitLoopback, FwpConst.FWPM_FILTER_FLAG_PERSISTENT, [user, loop]));
            foreach (var app in apps)
            {
                var appCond = new WfpConditionSpec(FwpGuids.ConditionAleAppId, "ALE_APP_ID", FwpConst.FWP_MATCH_EQUAL,
                    FwpConst.FWP_BYTE_BLOB_TYPE, app);
                list.Add(new WfpFilterSpec(FilterKey(rule.Sid, layer, "app", app), layer, name, "app", app,
                    FwpConst.FWP_ACTION_PERMIT, WeightPermitApp, FwpConst.FWPM_FILTER_FLAG_PERSISTENT, [user, appCond]));
            }
            list.Add(new WfpFilterSpec(FilterKey(rule.Sid, layer, "block", null), layer, name, "block", null,
                FwpConst.FWP_ACTION_BLOCK, WeightBlock,
                FwpConst.FWPM_FILTER_FLAG_PERSISTENT | FwpConst.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, [user]));
        }
        return list;
    }

    public static Guid FilterKey(string sid, Guid layer, string kind, string? app)
    {
        var bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(
            $"mincontrol/wfp/{Revision}/{sid.ToUpperInvariant()}/{layer:N}/{kind}/{app?.ToUpperInvariant()}"));
        var g = bytes.AsSpan(0, 16).ToArray();
        g[7] = (byte)((g[7] & 0x0F) | 0x50);   // version 5-style
        g[8] = (byte)((g[8] & 0x3F) | 0x80);   // RFC 4122 variant
        return new Guid(g);
    }

    public static string LayerName(Guid layer) =>
        Layers.FirstOrDefault(l => l.Layer == layer).Name ?? layer.ToString();

    public static string ActionName(uint action) => action switch
    {
        FwpConst.FWP_ACTION_BLOCK => "block",
        FwpConst.FWP_ACTION_PERMIT => "permit",
        _ => $"0x{action:X}",
    };

    public static string FieldName(Guid field) =>
        field == FwpGuids.ConditionAleUserId ? "ALE_USER_ID"
        : field == FwpGuids.ConditionAleAppId ? "ALE_APP_ID"
        : field == FwpGuids.ConditionFlags ? "FLAGS"
        : field.ToString();
}
