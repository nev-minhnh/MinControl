using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MinControl.Core.Abstractions;

namespace MinControl.NetGuard.Web;

/// <summary>Vietnamese texts of the "blocked" toast shown in the child's session.</summary>
public static class BlockNoticeText
{
    /// <summary>Policy category → Vietnamese display name (unknown categories are shown as-is).</summary>
    public static string CategoryName(string? category) => category?.ToLowerInvariant() switch
    {
        "adult" => "Người lớn",
        "gambling" => "Cờ bạc",
        "proxy-vpn" => "VPN/Proxy",
        "games" => "Trò chơi",
        "social" => "Mạng xã hội",
        "video" => "Video",
        "violence" => "Bạo lực",
        "drugs" => "Chất cấm",
        "dating" => "Hẹn hò",
        "malware" => "Mã độc",
        null or "" => "Không rõ",
        _ => category,
    };

    public static string Title(string what) => $"MinControl đã chặn {what}";

    /// <summary>Reason line for a proxy decision (<see cref="BlockReasons"/>).</summary>
    public static string Reason(string? reason, string? category) => reason switch
    {
        BlockReasons.Category => $"Danh mục: {CategoryName(category)}",
        BlockReasons.Schedule => $"Danh mục: {CategoryName(category)} · đang trong giờ học",
        BlockReasons.AllowlistMiss => "Chỉ được vào các trang cho phép",
        BlockReasons.Doh => "Chặn DNS mã hoá",
        BlockReasons.Port => "Cổng không được phép",
        _ => "Trang nằm trong danh sách chặn",
    };
}

/// <summary>Shows the "blocked" toast for a proxy decision. Implementations must never throw or block.</summary>
public interface IBlockNotifier
{
    void NotifyWebBlocked(string sid, string host, WebDecision decision);
}

/// <summary>Forwards to <see cref="ISessionActions.ShowBlockedNoticeAsync"/> (resolved lazily: the Service registers
/// it after NetGuard; rate limiting lives there). Fire-and-forget.</summary>
public sealed class SessionBlockNotifier(IServiceProvider services, ILogger<SessionBlockNotifier>? log = null) : IBlockNotifier
{
    private readonly ILogger _log = (ILogger?)log ?? NullLogger.Instance;

    public void NotifyWebBlocked(string sid, string host, WebDecision decision)
    {
        ISessionActions? actions;
        try { actions = services.GetService<ISessionActions>(); }
        catch (Exception ex) { _log.LogDebug(ex, "ISessionActions unavailable"); return; }
        if (actions is null) return;
        var title = BlockNoticeText.Title(host);
        var reason = BlockNoticeText.Reason(decision.Reason, decision.Category);
        _ = Task.Run(async () =>
        {
            try { await actions.ShowBlockedNoticeAsync(sid, title, reason, CancellationToken.None).ConfigureAwait(false); }
            catch (Exception ex) { _log.LogDebug(ex, "blocked notice failed"); }
        });
    }
}
