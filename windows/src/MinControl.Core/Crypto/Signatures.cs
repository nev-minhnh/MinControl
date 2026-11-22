using System.Security.Cryptography;
using NSec.Cryptography;

namespace MinControl.Core.Crypto;

/// <summary>Signature primitives used by the protocol (protocol/README.md §Signing rules).</summary>
public static class Signatures
{
    public const string Ed25519 = "ed25519", Es256 = "es256";

    /// <summary>keyId = first 16 hex chars of SHA-256 of the raw public key (Ed25519 32 B; P-256 uncompressed SEC1 65 B).</summary>
    public static string KeyId(ReadOnlySpan<byte> rawPublicKey) =>
        Convert.ToHexStringLower(SHA256.HashData(rawPublicKey))[..16];

    public static bool IsValidPublicKey(string alg, byte[] pub) => alg switch
    {
        Ed25519 => pub.Length == 32 && PublicKey.TryImport(SignatureAlgorithm.Ed25519, pub, KeyBlobFormat.RawPublicKey, out _),
        Es256 => pub.Length == 65 && pub[0] == 0x04 && TryP256(pub, out var k) && Dispose(k),
        _ => false,
    };

    /// <summary>Verifies <paramref name="sig"/> over the exact <paramref name="data"/> bytes. Never throws.</summary>
    public static bool Verify(string alg, byte[] pub, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig)
    {
        try
        {
            switch (alg)
            {
                case Ed25519:
                    if (pub.Length != 32 || sig.Length != 64) return false;
                    if (!PublicKey.TryImport(SignatureAlgorithm.Ed25519, pub, KeyBlobFormat.RawPublicKey, out var pk) || pk is null) return false;
                    return SignatureAlgorithm.Ed25519.Verify(pk, data, sig);
                case Es256:
                    if (pub.Length != 65 || pub[0] != 0x04 || sig.Length != 64) return false;
                    if (!TryP256(pub, out var ec)) return false;
                    using (ec)
                        return ec.VerifyData(data, sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                default:
                    return false;
            }
        }
        catch (CryptographicException) { return false; }
    }

    private static bool TryP256(byte[] pub, out ECDsa ec)
    {
        ec = null!;
        try
        {
            var p = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = pub[1..33], Y = pub[33..65] },
            };
            p.Validate();
            ec = ECDsa.Create(p);
            return true;
        }
        catch (CryptographicException) { return false; }
    }

    private static bool Dispose(IDisposable d) { d.Dispose(); return true; }
}
