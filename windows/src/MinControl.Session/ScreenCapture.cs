using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

namespace MinControl.Session;

/// <summary>GDI capture of the whole virtual screen (all monitors), resized to maxWidth, encoded as JPEG.
/// (DXGI Desktop Duplication would be faster/more robust for DRM/fullscreen-exclusive apps; GDI is the
/// accepted baseline.) The process is per-monitor DPI aware, so coordinates are physical pixels.</summary>
internal static class ScreenCapture
{
    public static (byte[] Jpeg, int Width, int Height) CaptureJpeg(int maxWidth, int quality)
    {
        var vs = SystemInformation.VirtualScreen;
        if (vs.Width <= 0 || vs.Height <= 0) throw new InvalidOperationException("no screen");
        using var full = new Bitmap(vs.Width, vs.Height, PixelFormat.Format24bppRgb);
        using (var g = Graphics.FromImage(full))
            g.CopyFromScreen(vs.Left, vs.Top, 0, 0, vs.Size, CopyPixelOperation.SourceCopy);

        var scale = Math.Min(1.0, Math.Max(160, maxWidth) / (double)vs.Width);
        var w = Math.Max(1, (int)Math.Round(vs.Width * scale));
        var h = Math.Max(1, (int)Math.Round(vs.Height * scale));
        using var resized = scale < 1.0 ? Resize(full, w, h) : null;
        var image = resized ?? full;

        var codec = ImageCodecInfo.GetImageEncoders().First(c => c.FormatID == ImageFormat.Jpeg.Guid);
        using var parameters = new EncoderParameters(1);
        parameters.Param[0] = new EncoderParameter(Encoder.Quality, (long)Math.Clamp(quality, 10, 95));
        using var ms = new MemoryStream();
        image.Save(ms, codec, parameters);
        return (ms.ToArray(), w, h);
    }

    private static Bitmap Resize(Bitmap source, int w, int h)
    {
        var dst = new Bitmap(w, h, PixelFormat.Format24bppRgb);
        using var g = Graphics.FromImage(dst);
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.DrawImage(source, 0, 0, w, h);
        return dst;
    }
}
