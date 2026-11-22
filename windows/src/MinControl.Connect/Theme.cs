using System.Drawing.Text;

namespace MinControl.Connect;

/// <summary>App look: Be Vietnam Pro (fallback Segoe UI), accent #2F54EB, white surface.</summary>
internal static class Theme
{
    public static readonly Color Accent = ColorTranslator.FromHtml("#2F54EB");
    public static readonly Color AccentHover = ColorTranslator.FromHtml("#1D39C4");
    public static readonly Color Ink = ColorTranslator.FromHtml("#1F1F1F");
    public static readonly Color Muted = ColorTranslator.FromHtml("#595959");
    public static readonly Color Ok = ColorTranslator.FromHtml("#389E0D");
    public static readonly Color Bad = ColorTranslator.FromHtml("#CF1322");

    public static readonly string Family = PickFont();

    public static Font Font(float size, FontStyle style = FontStyle.Regular) => new(Family, size, style);

    public static Button PrimaryButton(string text)
    {
        var b = new Button
        {
            Text = text, AutoSize = false, Size = new Size(170, 42), FlatStyle = FlatStyle.Flat,
            BackColor = Accent, ForeColor = Color.White, Font = Font(11f, FontStyle.Bold), Cursor = Cursors.Hand,
        };
        b.FlatAppearance.BorderSize = 0;
        b.FlatAppearance.MouseOverBackColor = AccentHover;
        return b;
    }

    public static Label Text(string text, float size = 10f, FontStyle style = FontStyle.Regular, Color? color = null, int maxWidth = 440) => new()
    {
        Text = text, AutoSize = true, MaximumSize = new Size(maxWidth, 0), Font = Font(size, style), ForeColor = color ?? Ink,
    };

    public static void Apply(Form f, string title)
    {
        f.Text = title;
        f.Font = Font(10f);
        f.BackColor = Color.White;
        f.ForeColor = Ink;
        f.FormBorderStyle = FormBorderStyle.FixedSingle;
        f.MaximizeBox = false;
        f.StartPosition = FormStartPosition.CenterScreen;
        f.AutoScaleMode = AutoScaleMode.Dpi;
        try { f.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch (Exception e) when (e is ArgumentException or IOException) { }
    }

    private static string PickFont()
    {
        using var fonts = new InstalledFontCollection();
        return fonts.Families.Any(f => f.Name.Equals("Be Vietnam Pro", StringComparison.OrdinalIgnoreCase)) ? "Be Vietnam Pro" : "Segoe UI";
    }
}
