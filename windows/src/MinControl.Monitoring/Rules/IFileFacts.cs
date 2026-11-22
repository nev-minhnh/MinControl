namespace MinControl.Monitoring.Rules;

/// <summary>Authenticode result for one file. <see cref="Publisher"/> is the signer subject CN and is
/// only set when the signature verified (embedded signature, chain trusted, no revocation check).</summary>
public sealed record SignatureInfo(bool Signed, string? Publisher)
{
    public static readonly SignatureInfo Unsigned = new(false, null);
}

/// <summary>Expensive per-file facts, evaluated lazily by <see cref="AppRuleEvaluator"/> only when a rule
/// needs them. The production implementation caches by path + size + mtime.</summary>
public interface IFileFacts
{
    /// <summary>Lower-case hex sha256, or null if the file cannot be read.</summary>
    string? Sha256(string path);
    SignatureInfo Signature(string path);
    long? SizeBytes(string path);
}
