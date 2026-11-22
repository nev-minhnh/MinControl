namespace MinControl.Setup;

/// <summary>Pairing QR payload (API.md §12, v2). Standalone so the tests can link this file.</summary>
internal static class PairingQr
{
    public static string Build(string serverUrl, string claimId, string fingerprint) =>
        $"mincontrol://pair?v=2&u={Uri.EscapeDataString(serverUrl)}&c={Uri.EscapeDataString(claimId)}&f={Uri.EscapeDataString(fingerprint)}";
}
