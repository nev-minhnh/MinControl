using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using MinControl.Monitoring.Native;

namespace MinControl.Monitoring.Rules;

/// <summary>
/// Production <see cref="IFileFacts"/>: sha256 and Authenticode publisher cached by
/// (path, size, last-write time) so a replaced file is re-evaluated. Thread-safe.
/// </summary>
internal sealed class FileFactsCache : IFileFacts
{
    private const int MaxEntries = 8192;

    private sealed class Entry
    {
        public string? Sha256;
        public bool ShaDone;
        public SignatureInfo? Signature;
    }

    private readonly record struct Key(string Path, long Size, long MTime);

    private readonly ConcurrentDictionary<Key, Entry> _cache = new();

    public long? SizeBytes(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            return fi.Exists ? fi.Length : null;
        }
        catch { return null; }
    }

    public string? Sha256(string path)
    {
        var e = GetEntry(path);
        if (e is null) return null;
        lock (e)
        {
            if (!e.ShaDone)
            {
                e.Sha256 = ComputeSha256(path);
                e.ShaDone = true;
            }
            return e.Sha256;
        }
    }

    public SignatureInfo Signature(string path)
    {
        var e = GetEntry(path);
        if (e is null) return SignatureInfo.Unsigned;
        lock (e)
        {
            return e.Signature ??= VerifyAuthenticode(path);
        }
    }

    private Entry? GetEntry(string path)
    {
        FileInfo fi;
        try
        {
            fi = new FileInfo(path);
            if (!fi.Exists) return null;
        }
        catch { return null; }

        if (_cache.Count > MaxEntries) _cache.Clear();
        return _cache.GetOrAdd(new Key(path.ToUpperInvariant(), fi.Length, fi.LastWriteTimeUtc.Ticks), _ => new Entry());
    }

    internal static string? ComputeSha256(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                1 << 16, FileOptions.SequentialScan);
            return Convert.ToHexStringLower(SHA256.HashData(fs));
        }
        catch
        {
            return null;
        }
    }

    /// <summary>WinVerifyTrust (embedded signature, no revocation/network) + signer leaf CN.
    /// Catalog-signed system binaries report unsigned here; they are covered by the %windir% protection.</summary>
    internal static SignatureInfo VerifyAuthenticode(string path)
    {
        IntPtr pPath = Marshal.StringToHGlobalUni(path);
        IntPtr pFile = IntPtr.Zero;
        var action = NativeMethods.WINTRUST_ACTION_GENERIC_VERIFY_V2;
        var data = new NativeMethods.WINTRUST_DATA();
        try
        {
            var fileInfo = new NativeMethods.WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>(),
                pcwszFilePath = pPath,
            };
            pFile = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, pFile, false);

            data.cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_DATA>();
            data.dwUIChoice = NativeMethods.WTD_UI_NONE;
            data.fdwRevocationChecks = NativeMethods.WTD_REVOKE_NONE;
            data.dwUnionChoice = NativeMethods.WTD_CHOICE_FILE;
            data.pFile = pFile;
            data.dwStateAction = NativeMethods.WTD_STATEACTION_VERIFY;
            data.dwProvFlags = NativeMethods.WTD_REVOCATION_CHECK_NONE | NativeMethods.WTD_CACHE_ONLY_URL_RETRIEVAL;

            int hr = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            if (hr != 0) return SignatureInfo.Unsigned;

            string? cn = null;
            IntPtr prov = NativeMethods.WTHelperProvDataFromStateData(data.hWVTStateData);
            if (prov != IntPtr.Zero)
            {
                IntPtr sgnr = NativeMethods.WTHelperGetProvSignerFromChain(prov, 0, false, 0);
                if (sgnr != IntPtr.Zero)
                {
                    IntPtr provCert = NativeMethods.WTHelperGetProvCertFromChain(sgnr, 0);
                    if (provCert != IntPtr.Zero)
                    {
                        // CRYPT_PROVIDER_CERT { DWORD cbStruct; PCCERT_CONTEXT pCert; ... } - pointer is pointer-aligned
                        IntPtr certCtx = Marshal.ReadIntPtr(provCert, IntPtr.Size);
                        cn = CertSimpleName(certCtx);
                    }
                }
            }
            return new SignatureInfo(true, cn);
        }
        catch
        {
            return SignatureInfo.Unsigned;
        }
        finally
        {
            if (data.hWVTStateData != IntPtr.Zero)
            {
                data.dwStateAction = NativeMethods.WTD_STATEACTION_CLOSE;
                NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            }
            if (pFile != IntPtr.Zero) Marshal.FreeHGlobal(pFile);
            Marshal.FreeHGlobal(pPath);
        }
    }

    private static string? CertSimpleName(IntPtr certCtx)
    {
        if (certCtx == IntPtr.Zero) return null;
        uint len = NativeMethods.CertGetNameStringW(certCtx, NativeMethods.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, IntPtr.Zero, null, 0);
        if (len <= 1) return null;
        var sb = new StringBuilder((int)len);
        NativeMethods.CertGetNameStringW(certCtx, NativeMethods.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, IntPtr.Zero, sb, len);
        var s = sb.ToString();
        return s.Length == 0 ? null : s;
    }
}
