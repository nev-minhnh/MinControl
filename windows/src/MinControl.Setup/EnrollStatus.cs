using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32;
using MinControl.Core.Storage;

namespace MinControl.Setup;

/// <summary>Result of one <c>MinControl.Setup enroll</c> run.</summary>
/// <param name="Ok">true = this PC is enrolled (fresh or already).</param>
/// <param name="Reason">machine code: ok, already_enrolled, bad_format, invalid_code, rejected, no_master,
/// no_server, server, network, error.</param>
/// <param name="Message">one Vietnamese sentence for the parent (MSI Finish dialog, connect tool).</param>
internal sealed record EnrollOutcome(bool Ok, string Reason, string Message, string? DeviceId = null, string? Detail = null)
{
    public static EnrollOutcome Fail(string reason, string message, string? detail = null) => new(false, reason, message, null, detail);
}

/// <summary>
/// Records the last enrolment attempt so that the installer UI and the connect tool can show it:
/// <list type="bullet">
/// <item><c>%ProgramData%\MinControl\enroll-status.json</c> (full record, SYSTEM/Administrators-only folder, I7)</item>
/// <item><c>HKLM\SOFTWARE\MinControl</c> values <c>EnrollState</c> (ok|failed), <c>EnrollReason</c>, <c>EnrollMessage</c>,
///   <c>EnrollAttempt</c>, <c>EnrollAt</c>: a non-secret mirror readable by the non-elevated msiexec UI process
///   (the data folder is not). Never contains the pairing code or any key material.</item>
/// </list>
/// </summary>
internal static class EnrollStatus
{
    public const string FileName = "enroll-status.json";
    public const string RegPath = @"SOFTWARE\MinControl";
    private static readonly string[] Values = ["EnrollState", "EnrollReason", "EnrollMessage", "EnrollAttempt", "EnrollAt"];

    public static string PathIn(string dataRoot) => Path.Combine(dataRoot, FileName);

    public static void Write(DataPaths paths, EnrollOutcome o, string? attempt, bool mirrorToRegistry)
    {
        var at = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
        var json = new JsonObject
        {
            ["state"] = o.Ok ? "ok" : "failed",
            ["reason"] = o.Reason,
            ["message"] = o.Message,
            ["detail"] = o.Detail,
            ["deviceId"] = o.DeviceId,
            ["attempt"] = attempt ?? "",
            ["at"] = at,
        };
        try
        {
            paths.EnsureExists();
            var path = PathIn(paths.Root);
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, json.ToJsonString(new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
            File.Move(tmp, path, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"warning: cannot write {FileName}: {e.Message}");
        }

        if (!mirrorToRegistry || !OperatingSystem.IsWindows()) return;
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.CreateSubKey(RegPath, writable: true);
            key.SetValue("EnrollState", o.Ok ? "ok" : "failed", RegistryValueKind.String);
            key.SetValue("EnrollReason", o.Reason, RegistryValueKind.String);
            key.SetValue("EnrollMessage", o.Message, RegistryValueKind.String);
            key.SetValue("EnrollAttempt", attempt ?? "", RegistryValueKind.String);
            key.SetValue("EnrollAt", at, RegistryValueKind.String);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Console.Error.WriteLine($"warning: cannot write HKLM\\{RegPath}: {e.Message}");
        }
    }

    /// <summary>Removes the record (unenroll / purge). Best effort.</summary>
    public static void Clear(DataPaths paths, bool registry)
    {
        foreach (var f in new[] { PathIn(paths.Root), Path.Combine(paths.Root, "claim.json"), Path.Combine(paths.Root, "device.pending.key") })
            try { File.Delete(f); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        if (!registry || !OperatingSystem.IsWindows()) return;
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(RegPath, writable: true);
            if (key is null) return;
            foreach (var v in Values) key.DeleteValue(v, throwOnMissingValue: false);
            var empty = key.ValueCount == 0 && key.SubKeyCount == 0;
            key.Close();
            if (empty) hklm.DeleteSubKey(RegPath, throwOnMissingSubKey: false);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.Security.SecurityException) { }
    }
}

/// <summary>Vietnamese messages shown to the parent (UI strings; code stays English).</summary>
internal static class EnrollMessages
{
    public const string Ok = "Đã kết nối. Chọn tài khoản của con trên điện thoại.";
    public const string Rejected = "Điện thoại đã từ chối ghép nối. Tạo mã QR mới để thử lại.";
    public const string Expired = "Mã QR đã hết hạn. Đang tạo mã mới.";
    public const string AlreadyEnrolled = "Máy này đã được kết nối với điện thoại từ trước.";
    public const string BadFormat = "Mã ghép nối phải gồm 8 ký tự (dạng XXXX-XXXX).";
    public const string InvalidCode = "Mã sai hoặc đã hết hạn. Tạo mã mới trên điện thoại rồi thử lại.";
    public const string NoMaster = "Máy chủ chưa có điện thoại cha mẹ nào được đăng ký.";
    public const string NoServer = "Chưa cấu hình địa chỉ máy chủ. Cài lại bằng bộ cài mới nhất.";
    public const string Server = "Máy chủ đang bận hoặc gặp lỗi. Thử lại sau ít phút.";
    public const string Network = "Không kết nối được máy chủ. Kiểm tra mạng Internet rồi thử lại.";
    public const string Error = "Có lỗi khi kết nối. Thử lại; nếu vẫn lỗi, gửi log cho người hỗ trợ.";
}
