using System.Drawing;
using Timer = System.Windows.Forms.Timer;

namespace MinControl.Session;

// The helper runs as SYSTEM on the child's desktop: keep the UI minimal (labels and one button, no text boxes,
// menus, dialogs or links) so it offers no shatter / "open file" escape into a SYSTEM context.

internal static class Texts
{
    public static string Title(string reason) => reason switch
    {
        "quota_exhausted" => "Đã hết thời gian dùng máy hôm nay",
        "outside_window" => "Bây giờ không phải giờ được dùng máy",
        "locked" => "Bố mẹ đã khóa máy",
        _ => "Máy sắp đăng xuất",
    };

    public static string Countdown(int seconds) => seconds > 0
        ? $"Máy sẽ tự đăng xuất sau {seconds / 60:00}:{seconds % 60:00}. Hãy lưu bài ngay!"
        : "Đang đăng xuất…";

    public static Font Font(float size, FontStyle style = FontStyle.Regular) => new("Segoe UI", size, style, GraphicsUnit.Point);
}

/// <summary>One full-screen topmost overlay per monitor with a shared countdown.</summary>
internal sealed class OverlayManager
{
    private readonly List<OverlayForm> _forms = new();
    private readonly Timer _tick = new() { Interval = 1_000 };
    private DateTime _deadlineUtc;
    private string _reason = "";

    public OverlayManager() => _tick.Tick += (_, _) => Refresh();

    /// <summary>Shows or updates the overlay. The service re-sends it every few seconds with the authoritative
    /// remaining time, so the local countdown is only cosmetic.</summary>
    public void Show(string reason, int secondsLeft)
    {
        _reason = reason;
        _deadlineUtc = DateTime.UtcNow.AddSeconds(Math.Max(0, secondsLeft));
        var screens = Screen.AllScreens;
        if (_forms.Count != screens.Length || _forms.Any(f => f.IsDisposed)
            || !_forms.Select(f => f.ScreenBounds).SequenceEqual(screens.Select(s => s.Bounds)))
        {
            CloseAll();
            foreach (var s in screens) _forms.Add(new OverlayForm(s.Bounds));
        }
        Refresh();
        foreach (var f in _forms) if (!f.Visible) f.Show();
        _tick.Start();
    }

    public void Hide()
    {
        _tick.Stop();
        CloseAll();
    }

    private void Refresh()
    {
        var left = (int)Math.Ceiling(Math.Max(0, (_deadlineUtc - DateTime.UtcNow).TotalSeconds));
        foreach (var f in _forms) f.Update(Texts.Title(_reason), Texts.Countdown(left));
    }

    private void CloseAll()
    {
        foreach (var f in _forms) f.ForceClose();
        _forms.Clear();
    }
}

internal sealed class OverlayForm : Form
{
    private readonly Label _title = new();
    private readonly Label _detail = new();
    private bool _allowClose;

    public Rectangle ScreenBounds { get; }

    public OverlayForm(Rectangle bounds)
    {
        ScreenBounds = bounds;
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        Bounds = bounds;
        TopMost = true;
        ShowInTaskbar = false;
        ControlBox = false;
        KeyPreview = true;
        AutoScaleMode = AutoScaleMode.None;
        BackColor = Color.FromArgb(18, 18, 24);
        ForeColor = Color.White;

        _title.Font = Texts.Font(32, FontStyle.Bold);
        _detail.Font = Texts.Font(18);
        foreach (var l in new[] { _title, _detail })
        {
            l.AutoSize = false;
            l.TextAlign = ContentAlignment.MiddleCenter;
            l.ForeColor = Color.White;
            l.BackColor = Color.Transparent;
            Controls.Add(l);
        }
        Layout += (_, _) =>
        {
            var w = ClientSize.Width;
            var h = ClientSize.Height;
            _title.SetBounds(0, h / 2 - 140, w, 120);
            _detail.SetBounds(0, h / 2 - 10, w, 80);
        };
        var keepOnTop = new Timer { Interval = 1_000 };
        keepOnTop.Tick += (_, _) =>
        {
            if (!IsDisposed)
                Native.SetWindowPos(Handle, Native.HWND_TOPMOST, 0, 0, 0, 0, Native.SWP_NOMOVE | Native.SWP_NOSIZE | Native.SWP_NOACTIVATE);
        };
        Shown += (_, _) => keepOnTop.Start();
        FormClosed += (_, _) => keepOnTop.Dispose();
    }

    public void Update(string title, string detail)
    {
        if (IsDisposed) return;
        _title.Text = title;
        _detail.Text = detail;
    }

    public void ForceClose()
    {
        _allowClose = true;
        if (!IsDisposed) Close();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        // Alt+F4 / user close is ignored; only the service (clear_overlay) or Windows shutdown/logoff closes it.
        if (!_allowClose && e.CloseReason == CloseReason.UserClosing) e.Cancel = true;
        base.OnFormClosing(e);
    }
}

/// <summary>Non-activating corner toast: "N minutes left".</summary>
internal sealed class ToastForm : Form
{
    private const int WS_EX = Native.WS_EX_TOPMOST | Native.WS_EX_TOOLWINDOW | Native.WS_EX_NOACTIVATE;

    public ToastForm(int minutes)
    {
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        TopMost = true;
        ShowInTaskbar = false;
        BackColor = Color.FromArgb(32, 33, 44);
        ForeColor = Color.White;
        Padding = new Padding(16);
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(380, 120);

        var title = new Label
        {
            Text = $"Còn {minutes} phút dùng máy", Font = Texts.Font(15, FontStyle.Bold), Dock = DockStyle.Top,
            Height = 40, ForeColor = Color.FromArgb(255, 200, 80),
        };
        var body = new Label
        {
            Text = "Hãy lưu bài và chuẩn bị nghỉ nhé.", Font = Texts.Font(11), Dock = DockStyle.Fill,
        };
        Controls.Add(body);
        Controls.Add(title);

        var area = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1024, 768);
        Location = new Point(area.Right - Width - 16, area.Bottom - Height - 16);

        var close = new Timer { Interval = 15_000 };
        close.Tick += (_, _) => { close.Dispose(); Close(); };
        Shown += (_, _) => close.Start();
        FormClosed += (_, _) => close.Dispose();
    }

    protected override bool ShowWithoutActivation => true;

    protected override CreateParams CreateParams
    {
        get
        {
            var cp = base.CreateParams;
            cp.ExStyle |= WS_EX;
            return cp;
        }
    }
}

/// <summary>Non-activating corner toast "MinControl đã chặn …" + reason line; closes itself after 5 s.
/// Never takes focus (WS_EX_NOACTIVATE + ShowWithoutActivation) and is not clickable into anything.</summary>
internal sealed class BlockedToastForm : Form
{
    private const int WS_EX = Native.WS_EX_TOPMOST | Native.WS_EX_TOOLWINDOW | Native.WS_EX_NOACTIVATE;
    public const int VisibleMs = 5_000;

    public BlockedToastForm(string title, string reason, int offsetAbove)
    {
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        TopMost = true;
        ShowInTaskbar = false;
        BackColor = Color.FromArgb(32, 33, 44);
        ForeColor = Color.White;
        Padding = new Padding(16, 12, 16, 12);
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(380, 96);

        var head = new Label
        {
            Text = title, Font = Texts.Font(12, FontStyle.Bold), Dock = DockStyle.Top, Height = 34,
            ForeColor = Color.FromArgb(255, 120, 110), AutoEllipsis = true, UseMnemonic = false,
        };
        var body = new Label
        {
            Text = reason, Font = Texts.Font(10.5f), Dock = DockStyle.Fill, AutoEllipsis = true, UseMnemonic = false,
        };
        Controls.Add(body);
        Controls.Add(head);
        if (AppIcon.Image is { } img)
        {
            Controls.Add(new PictureBox
            {
                Image = img, SizeMode = PictureBoxSizeMode.Zoom, Dock = DockStyle.Left, Width = 56,
                Padding = new Padding(0, 4, 12, 4),
            });
        }

        var area = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1024, 768);
        Location = new Point(area.Right - Width - 16, area.Bottom - Height - 16 - Math.Max(0, offsetAbove));

        var close = new Timer { Interval = VisibleMs };
        close.Tick += (_, _) => { close.Dispose(); Close(); };
        Shown += (_, _) => close.Start();
        FormClosed += (_, _) => close.Dispose();
    }

    protected override bool ShowWithoutActivation => true;

    protected override CreateParams CreateParams
    {
        get
        {
            var cp = base.CreateParams;
            cp.ExStyle |= WS_EX;
            return cp;
        }
    }
}

/// <summary>Message from the parent (command <c>message</c>).</summary>
internal sealed class MessageForm : Form
{
    public MessageForm(string text)
    {
        Text = "Tin nhắn từ bố mẹ";
        if (AppIcon.Icon is { } appIcon) Icon = appIcon;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        TopMost = true;
        ShowInTaskbar = true;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(480, 260);
        Padding = new Padding(16);

        var body = new Label { Text = text, Font = Texts.Font(13), Dock = DockStyle.Fill, AutoEllipsis = true };
        var ok = new Button { Text = "Đã đọc", Dock = DockStyle.Bottom, Height = 40, Font = Texts.Font(11) };
        ok.Click += (_, _) => Close();
        Controls.Add(body);
        Controls.Add(ok);
        AcceptButton = ok;
    }
}

/// <summary>The MinControl app icon (installed next to the exes as <c>mincontrol-512.png</c> / <c>mincontrol.ico</c>);
/// null when missing (dev builds) so the UI works without it.</summary>
internal static class AppIcon
{
    private static readonly Lazy<Image?> ImageLazy = new(() =>
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "mincontrol-512.png");
            if (!File.Exists(path)) return null;
            using var src = Image.FromFile(path);
            return new Bitmap(src, new Size(96, 96));
        }
        catch (Exception) { return null; }
    });

    private static readonly Lazy<Icon?> IconLazy = new(() =>
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "mincontrol.ico");
            return File.Exists(path) ? new Icon(path) : null;
        }
        catch (Exception) { return null; }
    });

    public static Image? Image => ImageLazy.Value;
    public static Icon? Icon => IconLazy.Value;
}
