namespace MinControl.Core.Events;

/// <summary>Vietnamese <c>detail</c> texts of the tamper.* events (shown as-is in the parent's timeline).</summary>
public static class TamperText
{
    public const string ServiceStopped = "Dịch vụ MinControl bị dừng bất thường";
    public const string HelperKilled = "Tiến trình MinControl trong phiên của con bị tắt quá 30 giây · đã đăng xuất phiên";
    public const string StateTampered = "Chính sách lưu trên máy bị sửa (sai chữ ký) · đã bỏ, chờ bố mẹ gửi lại";
    public const string ManagedUserIsAdmin = "Tài khoản của con có quyền quản trị (Administrator) · tạm ngưng kiểm soát";
    public const string WfpProviderRemoved = "Bộ lọc mạng của MinControl bị gỡ · đã cài lại";

    public static string WfpFiltersMissing(int count) => $"{count} bộ lọc mạng của MinControl bị gỡ · đã cài lại";

    public static string ClockJump(long jumpSec) =>
        $"Đồng hồ máy bị chỉnh {(jumpSec >= 0 ? "nhanh" : "chậm")} {Duration(Math.Abs(jumpSec))}";

    public static string TimezoneChanged(string from, string to) => $"Múi giờ của máy bị đổi: {from} → {to}";

    public static string OfflineGap(long gapSec) => $"Máy mất kết nối với MinControl trong {Duration(gapSec)}";

    public static string ExtensionMissing(string browser, long silentSec) =>
        $"Tiện ích MinControl trong {BrowserName(browser)} không hoạt động ({Duration(silentSec)})";

    public static string BrowserName(string browser) => browser.ToLowerInvariant() switch
    {
        "msedge" or "msedge.exe" => "Microsoft Edge",
        "chrome" or "chrome.exe" => "Google Chrome",
        _ => browser,
    };

    /// <summary>"45 giây", "12 phút", "3 giờ 5 phút".</summary>
    public static string Duration(long sec)
    {
        if (sec < 60) return $"{sec} giây";
        if (sec < 3600) return $"{sec / 60} phút";
        var h = sec / 3600;
        var m = sec % 3600 / 60;
        return m == 0 ? $"{h} giờ" : $"{h} giờ {m} phút";
    }
}
