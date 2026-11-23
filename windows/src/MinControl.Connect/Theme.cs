using System.Drawing.Text;

namespace MinControl.Connect;

/// <summary>App look: Be Vietnam Pro (fallback Segoe UI), accent #2F54EB, white surface, one centred column.
/// Pixel sizes are logical (96 DPI) and go through <see cref="Px(int)"/>; fonts are in points and scale on their own.</summary>
internal static class Theme
{
    public const string ProductName = "MinControl Connect";

    public static readonly Color Accent = ColorTranslator.FromHtml("#2F54EB");
    public static readonly Color AccentHover = ColorTranslator.FromHtml("#1D39C4");
    public static readonly Color AccentSoft = ColorTranslator.FromHtml("#F0F5FF");
    public static readonly Color Ink = ColorTranslator.FromHtml("#1F1F1F");
    public static readonly Color Muted = ColorTranslator.FromHtml("#595959");
    public static readonly Color Line = ColorTranslator.FromHtml("#E6E8F0");
    public static readonly Color Ok = ColorTranslator.FromHtml("#389E0D");
    public static readonly Color Bad = ColorTranslator.FromHtml("#CF1322");

    /// <summary>Logical width of the content column.</summary>
    public const int ColumnWidth = 400;

    public static readonly string Family = PickFont();

    private static int _dpi = 96;

    /// <summary>Logical pixels (96 DPI) to device pixels at the window's start-up DPI.</summary>
    public static int Px(int logical) => (int)Math.Round(logical * _dpi / 96.0);

    public static Size Px(int w, int h) => new(Px(w), Px(h));

    public static Padding Px(int left, int top, int right, int bottom) => new(Px(left), Px(top), Px(right), Px(bottom));

    public static Font Font(float size, FontStyle style = FontStyle.Regular) => new(Family, size, style);

    public static Button PrimaryButton(string text) => MakeButton(text, primary: true);

    public static Button SecondaryButton(string text) => MakeButton(text, primary: false);

    private static Button MakeButton(string text, bool primary)
    {
        var b = new Button
        {
            Text = text, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, MinimumSize = Px(150, 42),
            Padding = Px(14, 0, 14, 0), FlatStyle = FlatStyle.Flat, Anchor = AnchorStyles.None, UseMnemonic = false,
            BackColor = primary ? Accent : Color.White, ForeColor = primary ? Color.White : Accent,
            Font = Font(11f, FontStyle.Bold), Cursor = Cursors.Hand, Margin = Px(6, 0, 6, 0),
        };
        b.FlatAppearance.BorderSize = primary ? 0 : 1;
        b.FlatAppearance.BorderColor = Accent;
        b.FlatAppearance.MouseOverBackColor = primary ? AccentHover : AccentSoft;
        return b;
    }

    /// <summary>A centred, wrapping label (max width = the column).</summary>
    public static Label Text(string text, float size = 10f, FontStyle style = FontStyle.Regular, Color? color = null) => new()
    {
        Text = text, AutoSize = true, MaximumSize = new Size(Px(ColumnWidth), 0), Font = Font(size, style), ForeColor = color ?? Ink,
        TextAlign = ContentAlignment.TopCenter, Anchor = AnchorStyles.None, UseMnemonic = false,
    };

    /// <summary>The MinControl logo (embedded <c>mincontrol-512.png</c>) at <paramref name="logicalSize"/>.</summary>
    public static PictureBox Logo(int logicalSize = 64) => new()
    {
        Image = LogoImage, Size = Px(logicalSize, logicalSize), SizeMode = PictureBoxSizeMode.Zoom,
        Anchor = AnchorStyles.None, Margin = Px(0, 0, 0, 12), Visible = LogoImage is not null,
    };

    private static readonly Lazy<Image?> LogoLazy = new(() =>
    {
        try
        {
            using var s = typeof(Theme).Assembly.GetManifestResourceStream("MinControl.Logo.png");
            return s is null ? null : Image.FromStream(new MemoryStream(ReadAll(s)));
        }
        catch (Exception e) when (e is ArgumentException or IOException) { return null; }
    });

    public static Image? LogoImage => LogoLazy.Value;

    /// <summary>The multi-size app icon (embedded <c>mincontrol.ico</c>: 16 to 256 px), else the exe's own icon.</summary>
    public static Icon? AppIcon()
    {
        try
        {
            using var s = typeof(Theme).Assembly.GetManifestResourceStream("MinControl.Icon.ico");
            if (s is not null) return new Icon(new MemoryStream(ReadAll(s)));
            return Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        }
        catch (Exception e) when (e is ArgumentException or IOException or System.ComponentModel.Win32Exception) { return null; }
    }

    private static byte[] ReadAll(Stream s)
    {
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    /// <summary>Window chrome + size (logical px, clamped to the screen) + icon.</summary>
    public static void Apply(Form f, string title, int logicalWidth = 520, int logicalHeight = 720)
    {
        _dpi = f.DeviceDpi > 0 ? f.DeviceDpi : 96;
        f.Text = title;
        f.Font = Font(10f);
        f.BackColor = Color.White;
        f.ForeColor = Ink;
        f.FormBorderStyle = FormBorderStyle.FixedSingle;
        f.MaximizeBox = false;
        f.StartPosition = FormStartPosition.CenterScreen;
        // sizes come from Px() at the start-up DPI; moving to a monitor with another DPI rescales (PerMonitorV2)
        f.AutoScaleMode = AutoScaleMode.Dpi;
        var area = Screen.FromPoint(Cursor.Position).WorkingArea;
        f.ClientSize = new Size(Math.Min(Px(logicalWidth), area.Width - Px(40)), Math.Min(Px(logicalHeight), area.Height - Px(60)));
        if (AppIcon() is { } icon) f.Icon = icon;
    }

    private static string PickFont()
    {
        using var fonts = new InstalledFontCollection();
        return fonts.Families.Any(f => f.Name.Equals("Be Vietnam Pro", StringComparison.OrdinalIgnoreCase)) ? "Be Vietnam Pro" : "Segoe UI";
    }
}

/// <summary>
/// A page with one centred column of fixed width (<see cref="Theme.ColumnWidth"/>): every row is centred horizontally,
/// the column is centred in the page (vertically while it fits; the page scrolls otherwise).
/// </summary>
internal sealed class CenteredPage : Panel
{
    private readonly FlowLayoutPanel _column;

    public CenteredPage()
    {
        Dock = DockStyle.Fill;
        AutoScroll = true;
        BackColor = Color.White;
        _column = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = Color.White, Margin = Padding.Empty, Padding = Padding.Empty,
        };
        // zero-height strut: fixes the column width so the rows centre against it
        _column.Controls.Add(new Panel { Size = new Size(Theme.Px(Theme.ColumnWidth), 0), Margin = Padding.Empty });
        Controls.Add(_column);
    }

    /// <summary>Adds rows (top to bottom); each is centred horizontally.</summary>
    public void Add(params Control[] rows)
    {
        _column.SuspendLayout();
        foreach (var r in rows)
        {
            r.Anchor = AnchorStyles.None;
            _column.Controls.Add(r);
        }
        _column.ResumeLayout();
    }

    /// <summary>A horizontal row of buttons, centred in the column.</summary>
    public static FlowLayoutPanel ButtonRow(params Control[] buttons)
    {
        var row = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.LeftToRight, WrapContents = false, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            BackColor = Color.White, Margin = Theme.Px(0, 8, 0, 0), Padding = Padding.Empty, Anchor = AnchorStyles.None,
        };
        row.Controls.AddRange(buttons);
        return row;
    }

    protected override void OnLayout(LayoutEventArgs levent)
    {
        base.OnLayout(levent);
        if (_column is null) return;
        var pad = Theme.Px(24);
        var x = Math.Max(pad, (ClientSize.Width - _column.Width) / 2);
        var y = Math.Max(pad, (ClientSize.Height - _column.Height) * 2 / 5);   // a little above the centre
        var p = new Point(x + AutoScrollPosition.X, y + AutoScrollPosition.Y);
        if (_column.Location != p) _column.Location = p;
        var min = new Size(0, _column.Height + 2 * pad);
        if (AutoScrollMinSize != min) AutoScrollMinSize = min;
    }
}
