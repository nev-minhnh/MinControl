using System;
using System.Globalization;
using System.IO;
using Microsoft.Win32;
using WixToolset.Dtf.WindowsInstaller;

namespace MinControl.Installer.CA
{
    /// <summary>
    /// Immediate UI custom action (msiexec client, interactive user, NOT elevated). It never touches the system:
    /// it reads the non-secret enrolment mirror that MinControl.Setup writes
    /// to HKLM\SOFTWARE\MinControl (readable by Users; %ProgramData%\MinControl is not).
    /// Strings are set at runtime (Unicode), so they are free of the MSI database codepage.
    /// </summary>
    public static class CustomActions
    {
        /// <summary>
        /// "Expected stop" marker (same JSON as MinControl.Core.Storage.ExpectedStopMarker; the CA project does not
        /// reference Core): <c>{"at":"yyyy-MM-ddTHH:mm:ssZ","by":"msi"}</c> in %ProgramData%\MinControl\expected-stop.json,
        /// so the service does not report tamper.service_stopped for the stop this MSI is about to cause.
        /// IMMEDIATE (not deferred) on purpose: during a major upgrade the OLD product is removed inside
        /// RemoveExistingProducts, which runs (with its own StopServices) before this package's deferred script even
        /// starts, so a deferred action could never precede that stop. It is scheduled Before="InstallValidate" for
        /// upgrade/repair/uninstall and guarded by Privileged; elevated msiexec runs the execute sequence with the
        /// token that may write %ProgramData%\MinControl (SYSTEM/Administrators only). The folder is not created here
        /// (that would bypass its restricted ACL): without a folder there is no installed service to protect.
        /// Errors are ignored.
        /// </summary>
        [CustomAction]
        public static ActionResult WriteExpectedStop(Session session)
        {
            try
            {
                var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MinControl");
                if (!Directory.Exists(dir))
                {
                    session.Log("WriteExpectedStop: no data folder, skipped");
                    return ActionResult.Success;
                }
                var json = "{\"at\":\"" + DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture) + "\",\"by\":\"msi\"}";
                File.WriteAllText(Path.Combine(dir, "expected-stop.json"), json);
            }
            catch (Exception e)
            {
                session.Log("WriteExpectedStop: " + e.Message);
            }
            return ActionResult.Success;
        }

        /// <summary>
        /// After ExecuteAction (install succeeded). Fills the ExitDialog optional text and the
        /// "Mở màn hình kết nối" checkbox (checked) when this PC is not paired yet.
        /// </summary>
        [CustomAction]
        public static ActionResult ReadEnrollResult(Session session)
        {
            string state = null, reason = null, message = null, attempt = null;
            try
            {
                using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var key = hklm.OpenSubKey(@"SOFTWARE\MinControl"))
                {
                    state = key?.GetValue("EnrollState") as string;
                    reason = key?.GetValue("EnrollReason") as string;
                    message = key?.GetValue("EnrollMessage") as string;
                    attempt = key?.GetValue("EnrollAttempt") as string;
                }
            }
            catch (Exception e)
            {
                session.Log("ReadEnrollResult: " + e.Message);
            }

            var codeGiven = !string.IsNullOrEmpty(session["PAIRCODE"]);
            // A code was entered: the record must come from this very attempt (not a stale one).
            var fresh = !codeGiven || string.IsNullOrEmpty(session["MC_ATTEMPT"]) || attempt == session["MC_ATTEMPT"];
            var ok = fresh && state == "ok";
            session.Log($"ReadEnrollResult: state={state} reason={reason} fresh={fresh}");

            if (ok)
            {
                session["MC_ENROLLED"] = "1";
                session["WIXUI_EXITDIALOGOPTIONALTEXT"] = "Đã kết nối. Chọn tài khoản của con trên điện thoại.";
                session["WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT"] = "";
                session["WIXUI_EXITDIALOGOPTIONALCHECKBOX"] = "";
                return ActionResult.Success;
            }

            session["MC_ENROLLED"] = "";
            string why;
            if (!codeGiven)
                why = "Còn một bước: kết nối máy này với điện thoại bằng mã QR.";
            else if (!fresh || reason == "invalid_code" || reason == "bad_format" || string.IsNullOrEmpty(message))
                why = "Chưa kết nối được (mã sai/hết hạn).";
            else
                why = "Chưa kết nối được: " + message;
            session["WIXUI_EXITDIALOGOPTIONALTEXT"] = why +
                " Bấm Hoàn tất để mở màn hình kết nối, rồi quét mã QR bằng app MinControl trên điện thoại.";
            session["WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT"] = "Mở màn hình kết nối";
            session["WIXUI_EXITDIALOGOPTIONALCHECKBOX"] = "1";
            return ActionResult.Success;
        }
    }
}
