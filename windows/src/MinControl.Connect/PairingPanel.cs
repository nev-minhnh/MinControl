using System.Globalization;
using System.Text.Json.Nodes;
using QRCoder;

namespace MinControl.Connect;

/// <summary>
/// QR pairing screen (API.md §10): claim-start -> show QR + fingerprint + fallback code + countdown ->
/// claim-wait in a loop -> approved / rejected; an expired claim is replaced automatically.
/// Hosted by MinControl.Connect.exe and by the bootstrapper MinControl-Setup.exe.
/// </summary>
internal sealed class PairingPanel : UserControl
{
    private readonly SetupRunner _runner;
    private readonly Label _title, _hint, _fpCaption, _fingerprint, _code, _countdown, _status;
    private readonly PictureBox _qr;
    private readonly Button _action, _close;
    private readonly System.Windows.Forms.Timer _tick = new() { Interval = 1000 };
    private CancellationTokenSource? _cts;
    private DateTimeOffset _expires;
    private Action? _onAction;
    private bool _force;

    /// <summary>Raised when the user presses "Đóng" after a final state.</summary>
    public event EventHandler? CloseRequested;

    public bool Paired { get; private set; }

    public PairingPanel(SetupRunner runner)
    {
        _runner = runner;
        BackColor = Color.White;
        Dock = DockStyle.Fill;

        var page = new CenteredPage();
        var logo = Theme.Logo(56);
        _title = Theme.Text("Kết nối với điện thoại", 16f, FontStyle.Bold);
        _title.Margin = Theme.Px(0, 0, 0, 6);
        _hint = Theme.Text("Mở app MinControl trên điện thoại → bấm Quét mã → quét mã này. Lần đầu dùng, app sẽ tự thiết lập.", 10.5f, color: Theme.Muted);
        _hint.Margin = Theme.Px(0, 0, 0, 16);
        _qr = new PictureBox
        {
            Size = Theme.Px(248, 248), SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.White, Padding = Theme.Px(8, 8, 8, 8),
            Margin = Theme.Px(0, 0, 0, 14), Visible = false,
        };
        _qr.Paint += (_, e) =>
        {
            using var pen = new Pen(Theme.Line, Math.Max(1, Theme.Px(1)));
            e.Graphics.DrawRectangle(pen, 0, 0, _qr.Width - 1, _qr.Height - 1);
        };
        _fpCaption = Theme.Text("", 9.5f, color: Theme.Muted);
        _fpCaption.Margin = Theme.Px(0, 0, 0, 2);
        _fingerprint = Theme.Text("", 15f, FontStyle.Bold);
        _fingerprint.Margin = Theme.Px(0, 0, 0, 12);
        _code = Theme.Text("", 9.5f, color: Theme.Muted);
        _code.Margin = Theme.Px(0, 0, 0, 4);
        _countdown = Theme.Text("", 9.5f, color: Theme.Muted);
        _countdown.Margin = Theme.Px(0, 0, 0, 12);
        _status = Theme.Text("", 10.5f);
        _status.Margin = Theme.Px(0, 0, 0, 12);
        _action = Theme.PrimaryButton("Thử lại");
        _action.Visible = false;
        _action.Click += (_, _) => _onAction?.Invoke();
        _close = Theme.SecondaryButton("Đóng");
        _close.Visible = false;
        _close.Click += (_, _) => CloseRequested?.Invoke(this, EventArgs.Empty);

        page.Add(logo, _title, _hint, _qr, _fpCaption, _fingerprint, _code, _countdown, _status, CenteredPage.ButtonRow(_action, _close));
        Controls.Add(page);

        _tick.Tick += (_, _) => UpdateCountdown();
    }

    /// <summary>Starts (or restarts) pairing. <paramref name="force"/> = re-pair an already enrolled PC.</summary>
    public void Start(bool force = false)
    {
        _force = force;
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        _ = RunAsync(_cts.Token);
    }

    public void Stop()
    {
        _tick.Stop();
        _cts?.Cancel();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { Stop(); _tick.Dispose(); _cts?.Dispose(); }
        base.Dispose(disposing);
    }

    private async Task RunAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                ShowLoading();
                var start = await _runner.RunAsync(ct, _force ? ["claim-start", "--force"] : ["claim-start"]);
                switch ((string?)start["status"])
                {
                    case "already_enrolled":
                        ShowFinal("Máy này đã được kết nối với điện thoại.", Theme.Ok,
                            "Ghép nối lại", () => Start(force: true), showClose: true);
                        return;
                    case "ok":
                        break;
                    default:
                        ShowFinal(Msg(start, "Không tạo được mã QR."), Theme.Bad, "Thử lại", () => Start(_force));
                        return;
                }

                var claimId = (string)start["claimId"]!;
                ShowQr(start);
                while (!ct.IsCancellationRequested)
                {
                    var left = (int)Math.Floor((_expires - DateTimeOffset.UtcNow).TotalSeconds);
                    if (left <= 0) break;   // expired: new claim
                    var r = await _runner.RunAsync(ct, "claim-wait", claimId, "--timeout",
                        Math.Min(left, 30).ToString(CultureInfo.InvariantCulture), "--restart-service");
                    var status = (string?)r["status"];
                    if (status == "approved")
                    {
                        Paired = true;
                        ShowFinal(Msg(r, "Đã kết nối. Chọn tài khoản của con trên điện thoại."), Theme.Ok, null, null, showClose: true);
                        return;
                    }
                    if (status == "rejected")
                    {
                        ShowFinal(Msg(r, "Điện thoại đã từ chối ghép nối."), Theme.Bad, "Tạo mã mới", () => Start(_force));
                        return;
                    }
                    if (status == "expired" || (string?)r["reason"] == "no_claim") break;
                    if (status == "error")
                    {
                        SetStatus(Msg(r, "Có lỗi khi kết nối."), Theme.Bad);
                        await Task.Delay(3000, ct);
                        continue;
                    }
                    // pending: keep waiting; a message means the network is flaky
                    var m = (string?)r["message"];
                    SetStatus(string.IsNullOrEmpty(m) ? "Đang chờ điện thoại xác nhận…" : m, string.IsNullOrEmpty(m) ? Theme.Muted : Theme.Bad);
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    private static string Msg(JsonObject o, string fallback) => (string?)o["message"] is { Length: > 0 } m ? m : fallback;

    private void ShowLoading()
    {
        _tick.Stop();
        _qr.Visible = false;
        _fpCaption.Text = _fingerprint.Text = _code.Text = _countdown.Text = "";
        ShowQrDetails(false);
        _hint.Visible = true;
        _action.Visible = _close.Visible = false;
        SetStatus("Đang tạo mã QR…", Theme.Muted);
    }

    private void ShowQr(JsonObject s)
    {
        using (var gen = new QRCodeGenerator())
        using (var data = gen.CreateQrCode((string)s["qr"]!, QRCodeGenerator.ECCLevel.M))
        {
            var png = new PngByteQRCode(data).GetGraphic(10);
            var old = _qr.Image;
            _qr.Image = Image.FromStream(new MemoryStream(png));
            old?.Dispose();
        }
        var fp = (string?)s["fingerprint"] ?? "";
        _fpCaption.Text = "Mã nhận dạng máy (điện thoại phải hiện đúng mã này)";
        _fingerprint.Text = string.Join(" ", Enumerable.Range(0, fp.Length / 4).Select(i => fp.Substring(i * 4, 4)));
        _code.Text = $"Không quét được? Trong app chọn \"Nhập mã\": {(string?)s["code"]}";
        _expires = DateTimeOffset.TryParse((string?)s["expiresAt"], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var e)
            ? e : DateTimeOffset.UtcNow.AddMinutes(15);
        _qr.Visible = true;
        ShowQrDetails(true);
        _hint.Visible = true;
        _action.Visible = _close.Visible = false;
        SetStatus("Đang chờ điện thoại xác nhận…", Theme.Muted);
        UpdateCountdown();
        _tick.Start();
    }

    private void UpdateCountdown()
    {
        var left = _expires - DateTimeOffset.UtcNow;
        _countdown.Text = left > TimeSpan.Zero ? $"Mã hết hạn sau {(int)left.TotalMinutes}:{left.Seconds:00} (tự tạo mã mới)" : "Đang tạo mã mới…";
    }

    private void ShowFinal(string message, Color color, string? actionText, Action? action, bool showClose = false)
    {
        _tick.Stop();
        _qr.Visible = false;
        _hint.Visible = false;
        _fpCaption.Text = _fingerprint.Text = _code.Text = _countdown.Text = "";
        ShowQrDetails(false);
        SetStatus(message, color);
        _action.Visible = actionText is not null && action is not null;
        if (_action.Visible)
        {
            _action.Text = actionText;
            _onAction = action;
        }
        _close.Visible = showClose;
    }

    private void ShowQrDetails(bool visible) => _fpCaption.Visible = _fingerprint.Visible = _code.Visible = _countdown.Visible = visible;

    private void SetStatus(string text, Color color)
    {
        _status.Text = text;
        _status.ForeColor = color;
    }
}
