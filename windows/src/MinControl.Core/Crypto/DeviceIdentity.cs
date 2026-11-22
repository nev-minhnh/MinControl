using System.Security.Cryptography;
using System.Text;
using MinControl.Core.Storage;
using MinControl.Core.Util;
using NSec.Cryptography;

namespace MinControl.Core.Crypto;

/// <summary>Protects the device private key at rest.</summary>
public interface IKeyProtector
{
    byte[] Protect(byte[] secret);
    byte[] Unprotect(byte[] blob);
}

/// <summary>DPAPI with LocalMachine scope (I7): only code running on this machine can unprotect, and the
/// file itself is readable only by SYSTEM/Administrators through the directory ACL.</summary>
public sealed class DpapiMachineKeyProtector : IKeyProtector
{
    private static readonly byte[] Entropy = "MinControl.device.key.v1"u8.ToArray();

    public byte[] Protect(byte[] secret)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("DPAPI is Windows-only");
        return ProtectedData.Protect(secret, Entropy, DataProtectionScope.LocalMachine);
    }

    public byte[] Unprotect(byte[] blob)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("DPAPI is Windows-only");
        return ProtectedData.Unprotect(blob, Entropy, DataProtectionScope.LocalMachine);
    }
}

/// <summary>Device Ed25519 identity stored in <c>device.key</c> (magic "MCK1" + protected 32-byte seed).</summary>
public sealed class DeviceIdentity : IDisposable
{
    private static readonly byte[] Magic = "MCK1"u8.ToArray();
    private readonly string _path;
    private readonly IKeyProtector _protector;
    private readonly object _gate = new();
    private Key? _key;

    public DeviceIdentity(DataPaths paths, IKeyProtector protector) : this(paths.DeviceKey, protector) { }

    public DeviceIdentity(string keyPath, IKeyProtector protector)
    {
        _path = keyPath; _protector = protector;
    }

    public bool Exists => File.Exists(_path);

    /// <summary>Raw 32-byte Ed25519 public key; loads the key on first use.</summary>
    public byte[] PublicKey => Load().PublicKey.Export(KeyBlobFormat.RawPublicKey);

    /// <summary>Generates a fresh key and overwrites <c>device.key</c>. Enrolment (Setup) only.</summary>
    public byte[] CreateNew()
    {
        lock (_gate)
        {
            var seed = RandomNumberGenerator.GetBytes(32);
            try
            {
                var blob = _protector.Protect(seed);
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
                var tmp = _path + ".tmp";
                File.WriteAllBytes(tmp, [.. Magic, .. blob]);
                File.Move(tmp, _path, overwrite: true);
                _key?.Dispose();
                _key = Import(seed);
                return _key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
            }
            finally { CryptographicOperations.ZeroMemory(seed); }
        }
    }

    public byte[] Sign(ReadOnlySpan<byte> data) => SignatureAlgorithm.Ed25519.Sign(Load(), data);

    /// <summary>WS auth (API.md §2): b64url Ed25519 over UTF-8 <c>nonce + "|" + deviceId + "|" + ts</c>.</summary>
    public string AuthSignature(string nonce, string deviceId, string ts) =>
        Base64Url.Encode(Sign(Encoding.UTF8.GetBytes(nonce + "|" + deviceId + "|" + ts)));

    public void Delete()
    {
        lock (_gate)
        {
            _key?.Dispose(); _key = null;
            if (File.Exists(_path)) File.Delete(_path);
        }
    }

    public void Dispose() { lock (_gate) { _key?.Dispose(); _key = null; } }

    private Key Load()
    {
        lock (_gate)
        {
            if (_key is not null) return _key;
            if (!File.Exists(_path)) throw new InvalidOperationException("device is not enrolled (device.key missing)");
            var bytes = File.ReadAllBytes(_path);
            if (bytes.Length <= Magic.Length || !bytes.AsSpan(0, Magic.Length).SequenceEqual(Magic))
                throw new CryptographicException("device.key has an unknown format");
            var seed = _protector.Unprotect(bytes[Magic.Length..]);
            try
            {
                if (seed.Length != 32) throw new CryptographicException("device.key seed has the wrong length");
                return _key = Import(seed);
            }
            finally { CryptographicOperations.ZeroMemory(seed); }
        }
    }

    private static Key Import(byte[] seed) =>
        Key.Import(SignatureAlgorithm.Ed25519, seed, KeyBlobFormat.RawPrivateKey,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
}
