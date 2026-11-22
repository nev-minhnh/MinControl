using System.Runtime.InteropServices;

namespace MinControl.NetGuard.Wfp;

// Hand-written blittable P/Invoke for fwpuclnt.dll (x64/arm64 layouts follow natural C alignment).
// Only the subset needed by WfpManager. All pointers are IntPtr; memory is owned by the caller.

internal static class FwpConst
{
    // FWP_DATA_TYPE
    public const uint FWP_EMPTY = 0, FWP_UINT8 = 1, FWP_UINT16 = 2, FWP_UINT32 = 3, FWP_UINT64 = 4,
        FWP_BYTE_BLOB_TYPE = 12, FWP_SID = 13, FWP_SECURITY_DESCRIPTOR_TYPE = 14;

    // FWP_MATCH_TYPE
    public const uint FWP_MATCH_EQUAL = 0, FWP_MATCH_FLAGS_ALL_SET = 6;

    // FWP_ACTION_TYPE
    public const uint FWP_ACTION_FLAG_TERMINATING = 0x1000;
    public const uint FWP_ACTION_BLOCK = 0x1 | FWP_ACTION_FLAG_TERMINATING;
    public const uint FWP_ACTION_PERMIT = 0x2 | FWP_ACTION_FLAG_TERMINATING;

    // FWPM_FILTER_FLAG_*
    public const uint FWPM_FILTER_FLAG_PERSISTENT = 0x1, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT = 0x8;
    public const uint FWPM_PROVIDER_FLAG_PERSISTENT = 0x1;
    public const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 0x1;

    // FWP_CONDITION_FLAG_*
    public const uint FWP_CONDITION_FLAG_IS_LOOPBACK = 0x1;

    public const uint RPC_C_AUTHN_WINNT = 10;

    // Win32 / FWP error codes
    public const uint ERROR_SUCCESS = 0;
    public const uint FWP_E_ALREADY_EXISTS = 0x80320009;
    public const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;
    public const uint FWP_E_PROVIDER_NOT_FOUND = 0x80320005;
    public const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;
    public const uint FWP_E_NOT_FOUND = 0x80320008;
}

internal static class FwpGuids
{
    public static readonly Guid LayerAleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");
    public static readonly Guid LayerAleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
    public static readonly Guid LayerAleAuthRecvAcceptV4 = new("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
    public static readonly Guid LayerAleAuthRecvAcceptV6 = new("a3b42c97-9f04-4672-b87e-cee9c483257f");

    public static readonly Guid ConditionAleUserId = new("af043a0a-b34d-4f86-979c-c90371af6e66");
    public static readonly Guid ConditionAleAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");
    public static readonly Guid ConditionFlags = new("632ce23b-5167-435c-86d7-e903684aa80c");
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWP_BYTE_BLOB
{
    public uint size;
    public IntPtr data;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_DISPLAY_DATA0
{
    public IntPtr name;          // wchar_t*
    public IntPtr description;   // wchar_t*
}

/// <summary>FWP_VALUE0 / FWP_CONDITION_VALUE0: type + 8-byte union.</summary>
[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FWP_VALUE0
{
    [FieldOffset(0)] public uint type;
    [FieldOffset(8)] public ulong uint64;   // also holds uint8/16/32 (low bytes) and any pointer
    [FieldOffset(8)] public IntPtr ptr;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER_CONDITION0
{
    public Guid fieldKey;
    public uint matchType;
    public FWP_VALUE0 conditionValue;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_ACTION0
{
    public uint type;
    public Guid filterTypeOrCalloutKey;
}

[StructLayout(LayoutKind.Explicit, Size = 16)]
internal struct FWPM_FILTER_CONTEXT_UNION
{
    [FieldOffset(0)] public ulong rawContext;
    [FieldOffset(0)] public Guid providerContextKey;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_FILTER0
{
    public Guid filterKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public IntPtr providerKey;            // GUID*
    public FWP_BYTE_BLOB providerData;
    public Guid layerKey;
    public Guid subLayerKey;
    public FWP_VALUE0 weight;
    public uint numFilterConditions;
    public IntPtr filterCondition;        // FWPM_FILTER_CONDITION0*
    public FWPM_ACTION0 action;
    public FWPM_FILTER_CONTEXT_UNION context;
    public IntPtr reserved;               // GUID*
    public ulong filterId;
    public FWP_VALUE0 effectiveWeight;
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_PROVIDER0
{
    public Guid providerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public FWP_BYTE_BLOB providerData;
    public IntPtr serviceName;            // wchar_t*
}

[StructLayout(LayoutKind.Sequential)]
internal struct FWPM_SUBLAYER0
{
    public Guid subLayerKey;
    public FWPM_DISPLAY_DATA0 displayData;
    public uint flags;
    public IntPtr providerKey;            // GUID*
    public FWP_BYTE_BLOB providerData;
    public ushort weight;
}

internal static partial class WfpNative
{
    private const string Dll = "fwpuclnt.dll";

    [LibraryImport(Dll)]
    public static partial uint FwpmEngineOpen0(IntPtr serverName, uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);

    [LibraryImport(Dll)]
    public static partial uint FwpmEngineClose0(IntPtr engineHandle);

    [LibraryImport(Dll)]
    public static partial uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

    [LibraryImport(Dll)]
    public static partial uint FwpmTransactionCommit0(IntPtr engineHandle);

    [LibraryImport(Dll)]
    public static partial uint FwpmTransactionAbort0(IntPtr engineHandle);

    [LibraryImport(Dll)]
    public static partial uint FwpmProviderAdd0(IntPtr engineHandle, in FWPM_PROVIDER0 provider, IntPtr sd);

    [LibraryImport(Dll)]
    public static partial uint FwpmProviderDeleteByKey0(IntPtr engineHandle, in Guid key);

    [LibraryImport(Dll)]
    public static partial uint FwpmProviderGetByKey0(IntPtr engineHandle, in Guid key, out IntPtr provider);

    [LibraryImport(Dll)]
    public static partial uint FwpmSubLayerAdd0(IntPtr engineHandle, in FWPM_SUBLAYER0 subLayer, IntPtr sd);

    [LibraryImport(Dll)]
    public static partial uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, in Guid key);

    [LibraryImport(Dll)]
    public static partial uint FwpmSubLayerGetByKey0(IntPtr engineHandle, in Guid key, out IntPtr subLayer);

    [LibraryImport(Dll)]
    public static partial uint FwpmFilterAdd0(IntPtr engineHandle, in FWPM_FILTER0 filter, IntPtr sd, out ulong id);

    [LibraryImport(Dll)]
    public static partial uint FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);

    [LibraryImport(Dll)]
    public static partial uint FwpmFilterCreateEnumHandle0(IntPtr engineHandle, IntPtr enumTemplate, out IntPtr enumHandle);

    [LibraryImport(Dll)]
    public static partial uint FwpmFilterEnum0(IntPtr engineHandle, IntPtr enumHandle, uint numEntriesRequested, out IntPtr entries, out uint numEntriesReturned);

    [LibraryImport(Dll)]
    public static partial uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

    [LibraryImport(Dll)]
    public static partial void FwpmFreeMemory0(ref IntPtr p);

    [LibraryImport(Dll, StringMarshalling = StringMarshalling.Utf16)]
    public static partial uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);   // FWP_BYTE_BLOB**

    [LibraryImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision, out IntPtr sd, out uint size);

    [LibraryImport("kernel32.dll")]
    public static partial IntPtr LocalFree(IntPtr mem);
}

/// <summary>WFP call failed. <see cref="Code"/> is the raw DWORD/HRESULT.</summary>
public sealed class WfpException(string operation, uint code) : Exception($"{operation} failed: 0x{code:X8}")
{
    public uint Code { get; } = code;
}
