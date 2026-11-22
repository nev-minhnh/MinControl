using System.Diagnostics;
using System.Text.Json.Nodes;

namespace MinControl.Connect;

/// <summary>Runs the installed MinControl.Setup.exe (inherits our elevated token: no extra UAC prompt) and
/// returns the JSON object it prints as its last stdout line.</summary>
internal sealed class SetupRunner(string setupExe)
{
    public string SetupExe { get; } = setupExe;

    /// <summary>Install folder of the MSI (INSTALLFOLDER = ProgramFiles64Folder\MinControl).</summary>
    public static string InstalledSetupExe =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "MinControl", "MinControl.Setup.exe");

    public async Task<JsonObject> RunAsync(CancellationToken ct, params string[] args)
    {
        if (!File.Exists(SetupExe))
            return Error("Không tìm thấy MinControl.Setup.exe. Cài lại MinControl.");
        var psi = new ProcessStartInfo(SetupExe)
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi);
        if (p is null) return Error("Không chạy được MinControl.Setup.");
        var stdout = p.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var stderr = p.StandardError.ReadToEndAsync(CancellationToken.None);
        try
        {
            await p.WaitForExitAsync(ct);
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            throw;
        }
        var last = (await stdout).Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith('{'));
        try
        {
            if (last is not null && JsonNode.Parse(last) is JsonObject o) return o;
        }
        catch (System.Text.Json.JsonException) { }
        var err = (await stderr).Trim();
        return Error("Có lỗi khi kết nối. " + (err.Length > 200 ? err[..200] : err));
    }

    private static JsonObject Error(string message) => new() { ["status"] = "error", ["reason"] = "error", ["message"] = message };
}
