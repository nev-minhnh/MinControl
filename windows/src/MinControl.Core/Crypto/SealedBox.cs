using Sodium;

namespace MinControl.Core.Crypto;

/// <summary>libsodium <c>crypto_box_seal</c> (X25519 + XSalsa20-Poly1305) to the master seal key (API.md §7).</summary>
public static class SealedBox
{
    public const int Overhead = 48; // ephemeral pk (32) + MAC (16)

    public static byte[] Seal(byte[] plaintext, byte[] recipientX25519PublicKey)
    {
        if (recipientX25519PublicKey.Length != 32) throw new ArgumentException("seal key must be 32 bytes", nameof(recipientX25519PublicKey));
        return SealedPublicKeyBox.Create(plaintext, recipientX25519PublicKey);
    }
}
