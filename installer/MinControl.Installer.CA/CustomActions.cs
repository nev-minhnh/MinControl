using System;
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
