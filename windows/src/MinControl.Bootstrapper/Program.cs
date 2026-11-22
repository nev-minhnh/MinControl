using System.Diagnostics;
using MinControl.Connect;

namespace MinControl.Bootstrapper;

// MinControl-Setup.exe (elevated by manifest): Welcome -> silent MSI install -> QR pairing -> done.
// Advanced / scripted installs keep using the MSI directly: msiexec /i MinControl-x.y.z.msi PAIRCODE=XXXXXXXX /qn
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new SetupForm());
    }
}

internal sealed class SetupForm : Form
{
    private readonly Panel _host = new() { Dock = DockStyle.Fill, BackColor = Color.White };
    private PairingPanel? _pairing;
    private bool _installing;
    private bool _installed;

    public SetupForm()
    {
        Theme.Apply(this, "Cài đặt MinControl");
        ClientSize = new Size(500, 600);
        Controls.Add(_host);
        ShowWelcome();
        FormClosing += OnClosing;
    }

    private void OnClosing(object? sender, FormClosingEventArgs e)
    {
        if (_installing) { e.Cancel = true; return; }   // never abandon msiexec half-way
        if (_installed && _pairing is { Paired: false })
        {
            var r = MessageBox.Show(this,
                "MinControl đã được cài nhưng máy này chưa kết nối với điện thoại nên chưa dùng được.\n\n" +
                "Có thể kết nối sau: menu Start > \"Kết nối MinControl với điện thoại\".\n\nVẫn đóng?",
                Text, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (r != DialogResult.Yes) { e.Cancel = true; return; }
        }
        _pairing?.Stop();
    }

    private static FlowLayoutPanel Page()
    {
        return new FlowLayoutPanel
        {
            Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false,
            Padding = new Padding(28, 24, 28, 16), BackColor = Color.White,
        };
    }

    private void Swap(Control c)
    {
        var olds = _host.Controls.Cast<Control>().ToArray();
        _host.Controls.Clear();
        _host.Controls.Add(c);
        // dispose later: the old page may be the one raising the current Click event
        BeginInvoke(() => { foreach (var o in olds) o.Dispose(); });
    }

    private void ShowWelcome()
    {
        var page = Page();
        var title = Theme.Text("Cài đặt MinControl", 16f, FontStyle.Bold);
        title.Margin = new Padding(0, 0, 0, 12);
        var body = Theme.Text(
            "MinControl giúp cha mẹ quản lý thời gian dùng máy tính của con.\n\n" +
            "Cần chuẩn bị: điện thoại đã cài app MinControl và máy tính có Internet.\n\n" +
            "Sau khi cài xong, màn hình sẽ hiện một mã QR. Dùng app MinControl trên điện thoại quét mã đó và xác nhận là xong.",
            10.5f, color: Theme.Muted);
        body.Margin = new Padding(0, 0, 0, 24);
        var install = Theme.PrimaryButton("Cài đặt");
        install.Click += async (_, _) => await InstallAsync();
        page.Controls.AddRange([title, body, install]);
        AcceptButton = install;
        Swap(page);
    }

    private async Task InstallAsync()
    {
        var page = Page();
        var title = Theme.Text("Đang cài MinControl…", 16f, FontStyle.Bold);
        title.Margin = new Padding(0, 0, 0, 16);
        var bar = new ProgressBar { Style = ProgressBarStyle.Marquee, Width = 420, Height = 12, MarqueeAnimationSpeed = 30, Margin = new Padding(0, 0, 0, 12) };
        var note = Theme.Text("Việc này mất khoảng một phút. Đừng tắt máy.", 10f, color: Theme.Muted);
        page.Controls.AddRange([title, bar, note]);
        AcceptButton = null;
        Swap(page);

        _installing = true;
        var log = Path.Combine(Path.GetTempPath(), "MinControl-install.log");
        (bool ok, string message) result;
        try { result = await Task.Run(() => RunMsi(log)); }
        finally { _installing = false; }

        if (!result.ok) { ShowInstallError(result.message, log); return; }
        _installed = true;
        _pairing = new PairingPanel(new SetupRunner(SetupRunner.InstalledSetupExe));
        _pairing.CloseRequested += (_, _) => Close();
        Swap(_pairing);
        _pairing.Start();
    }

    private static (bool Ok, string Message) RunMsi(string log)
    {
        using var payload = typeof(SetupForm).Assembly.GetManifestResourceStream("MinControl.msi");
        if (payload is null) return (false, "Bộ cài bị thiếu dữ liệu (MSI). Hãy tải lại MinControl-Setup.exe.");
        var dir = Path.Combine(Path.GetTempPath(), "MinControl-Setup");
        Directory.CreateDirectory(dir);
        var msi = Path.Combine(dir, "MinControl.msi");
        using (var f = File.Create(msi)) payload.CopyTo(f);
        try
        {
            var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "msiexec.exe")) { UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in new[] { "/i", msi, "/qn", "/norestart", "/l*v", log }) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi) ?? throw new InvalidOperationException("msiexec did not start");
            p.WaitForExit();
            return p.ExitCode switch
            {
                0 or 3010 or 1641 => (true, ""),
                1618 => (false, "Windows đang cài một chương trình khác. Chờ cài xong rồi bấm Thử lại."),
                1638 => (false, "Máy đã có phiên bản MinControl khác. Gỡ bản cũ trong Cài đặt > Ứng dụng rồi thử lại."),
                1925 or 1303 => (false, "Cần quyền quản trị để cài MinControl."),
                _ => (false, $"Cài đặt thất bại (mã lỗi {p.ExitCode})."),
            };
        }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return (false, "Không chạy được Windows Installer: " + e.Message);
        }
        finally
        {
            try { File.Delete(msi); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        }
    }

    private void ShowInstallError(string message, string log)
    {
        var page = Page();
        var title = Theme.Text("Chưa cài được MinControl", 16f, FontStyle.Bold, Theme.Bad);
        title.Margin = new Padding(0, 0, 0, 12);
        var body = Theme.Text(message + "\n\nNhật ký cài đặt: " + log, 10f, color: Theme.Muted);
        body.Margin = new Padding(0, 0, 0, 24);
        var retry = Theme.PrimaryButton("Thử lại");
        retry.Click += async (_, _) => await InstallAsync();
        page.Controls.AddRange([title, body, retry]);
        Swap(page);
    }
}
