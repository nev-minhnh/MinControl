using System.Globalization;

namespace MinControl.Session;

internal static class Program
{
    /// <summary>Started only by MinControl.Service (as SYSTEM, in the user's session, on WinSta0\Default):
    /// <c>MinControl.Session.exe --session &lt;id&gt; --service-pid &lt;pid&gt;</c>.</summary>
    [STAThread]
    private static int Main(string[] args)
    {
        if (!TryArg(args, "--session", out var sessionId) || !TryArg(args, "--service-pid", out var servicePid))
            return 2;
        if (System.Diagnostics.Process.GetCurrentProcess().SessionId != sessionId) return 3;

        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, _) => { /* keep running; service restarts us if we die anyway */ };
        SynchronizationContext.SetSynchronizationContext(new WindowsFormsSynchronizationContext());

        using var context = new HelperContext(sessionId, servicePid);
        Application.Run(context);
        return 0;
    }

    private static bool TryArg(string[] args, string name, out int value)
    {
        value = 0;
        var i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length
            && int.TryParse(args[i + 1], NumberStyles.None, CultureInfo.InvariantCulture, out value) && value >= 0;
    }
}
