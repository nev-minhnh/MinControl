namespace MinControl.Connect;

// MinControl.Connect — elevated (manifest) window with the pairing QR code (PairingPanel).
// Started from the Start-menu shortcut "Kết nối MinControl với điện thoại", the MSI Finish dialog
// ("Mở màn hình kết nối") or "MinControl.Setup connect". Closing it leaves the agent installed but unpaired.
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new ConnectForm());
    }
}

internal sealed class ConnectForm : Form
{
    public ConnectForm()
    {
        Theme.Apply(this, "Kết nối MinControl với điện thoại");
        ClientSize = new Size(500, 600);
        var panel = new PairingPanel(new SetupRunner(Path.Combine(AppContext.BaseDirectory, "MinControl.Setup.exe")));
        panel.CloseRequested += (_, _) => Close();
        Controls.Add(panel);
        Shown += (_, _) => panel.Start();
        FormClosing += (_, _) => panel.Stop();
    }
}
