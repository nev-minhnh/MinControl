using System.Collections.Concurrent;
using System.Security.AccessControl;

namespace MinControl.Monitoring.Rules;

/// <summary>
/// The SIDs an access check is evaluated for: the managed user's SID plus its token groups.
/// <see cref="Enabled"/> SIDs match allow and deny ACEs; <see cref="DenyOnly"/> SIDs
/// (SE_GROUP_USE_FOR_DENY_ONLY) match deny ACEs only, exactly like the kernel access check.
/// </summary>
public sealed class PrincipalSet
{
    /// <summary>Groups every interactive local user token carries; used when no live token is available.</summary>
    public static readonly IReadOnlyList<string> WellKnownInteractiveGroups =
    [
        "S-1-1-0",      // Everyone
        "S-1-2-0",      // LOCAL
        "S-1-5-4",      // INTERACTIVE
        "S-1-5-11",     // Authenticated Users
        "S-1-5-15",     // This Organization
        "S-1-5-32-545", // BUILTIN\Users
        "S-1-5-113",    // Local account
    ];

    public PrincipalSet(string userSid, IEnumerable<string> enabled, IEnumerable<string>? denyOnly = null)
    {
        UserSid = userSid;
        Enabled = new HashSet<string>(enabled, StringComparer.OrdinalIgnoreCase) { userSid };
        DenyOnly = new HashSet<string>(denyOnly ?? [], StringComparer.OrdinalIgnoreCase);
        DenyOnly.ExceptWith(Enabled);
    }

    public string UserSid { get; }
    public HashSet<string> Enabled { get; }
    public HashSet<string> DenyOnly { get; }

    /// <summary>The user SID + the well-known interactive groups (user not logged on / token unavailable).</summary>
    public static PrincipalSet Fallback(string userSid) => new(userSid, WellKnownInteractiveGroups);

    internal bool MatchesAllow(string sid) => Enabled.Contains(sid);
    internal bool MatchesDeny(string sid) => Enabled.Contains(sid) || DenyOnly.Contains(sid);
}

/// <summary>
/// Pure DACL evaluation (manual ACE walk with the kernel's AccessCheck semantics). Used instead of
/// GetEffectiveRightsFromAcl, which mis-handles deny ACEs.
/// <list type="bullet">
/// <item>NULL DACL ⇒ everything is granted.</item>
/// <item>Owner ⇒ implicit READ_CONTROL | WRITE_DAC, unless the DACL has an OWNER RIGHTS (S-1-3-4) ACE; in that case
///   the owner is matched against those ACEs instead.</item>
/// <item>ACEs are walked in stored order (canonical or not); inherit-only ACEs are skipped; for every bit the first
///   matching allow/deny ACE decides. Generic rights are mapped with the file generic mapping.</item>
/// <item>Fail-closed for this purpose ("could the user write?"): callback/conditional allow ACEs count as allow,
///   callback deny ACEs are ignored, object ACEs are treated like plain ACEs.</item>
/// </list>
/// </summary>
public static class AclEvaluator
{
    public const int FileWriteData = 0x0002;       // file: write data   | directory: add file
    public const int FileAppendData = 0x0004;      // file: append data  | directory: add subdirectory
    public const int FileDeleteChild = 0x0040;     // directory: delete child
    public const int Delete = 0x0001_0000;
    public const int ReadControl = 0x0002_0000;
    public const int WriteDac = 0x0004_0000;
    public const int WriteOwner = 0x0008_0000;

    private const int GenericAll = 0x1000_0000;
    private const int GenericExecute = 0x2000_0000;
    private const int GenericWrite = 0x4000_0000;
    private const int GenericRead = unchecked((int)0x8000_0000);
    private const int FileGenericRead = 0x0012_0089;
    private const int FileGenericWrite = 0x0012_0116;
    private const int FileGenericExecute = 0x0012_00A0;
    private const int FileAllAccess = 0x001F_01FF;

    internal const string OwnerRightsSid = "S-1-3-4";

    /// <summary>Maps GENERIC_* bits to file-specific rights (FILE_GENERIC_* mapping).</summary>
    public static int MapGeneric(int mask)
    {
        int m = mask & ~(GenericAll | GenericExecute | GenericWrite | GenericRead);
        if ((mask & GenericAll) != 0) m |= FileAllAccess;
        if ((mask & GenericRead) != 0) m |= FileGenericRead;
        if ((mask & GenericWrite) != 0) m |= FileGenericWrite;
        if ((mask & GenericExecute) != 0) m |= FileGenericExecute;
        return m;
    }

    /// <summary>The subset of <paramref name="rights"/> the principals are granted by <paramref name="sd"/>.</summary>
    public static int GrantedRights(RawSecurityDescriptor sd, PrincipalSet who, int rights)
    {
        ArgumentNullException.ThrowIfNull(sd);
        ArgumentNullException.ThrowIfNull(who);
        var dacl = sd.DiscretionaryAcl;
        if (dacl is null || (sd.ControlFlags & ControlFlags.DiscretionaryAclPresent) == 0)
            return rights; // NULL DACL: full access for everyone

        bool isOwner = sd.Owner is { } owner && who.MatchesAllow(owner.Value);
        bool hasOwnerRightsAce = false;
        foreach (GenericAce ace in dacl)
        {
            if ((ace.AceFlags & AceFlags.InheritOnly) != 0) continue;
            if (ace is KnownAce k && string.Equals(k.SecurityIdentifier.Value, OwnerRightsSid, StringComparison.Ordinal))
            {
                hasOwnerRightsAce = true;
                break;
            }
        }

        int granted = 0, decided = 0;
        if (isOwner && !hasOwnerRightsAce)
        {
            granted |= (ReadControl | WriteDac) & rights;
            decided |= ReadControl | WriteDac;
        }

        foreach (GenericAce ace in dacl)
        {
            if ((decided & rights) == rights) break;
            if ((ace.AceFlags & AceFlags.InheritOnly) != 0) continue;
            if (ace is not KnownAce known) continue; // custom ACE types carry no SID/mask we understand

            string sid = known.SecurityIdentifier.Value;
            bool ownerRights = isOwner && string.Equals(sid, OwnerRightsSid, StringComparison.Ordinal);
            int mask = MapGeneric(known.AccessMask) & rights & ~decided;
            if (mask == 0) continue;

            switch (ace.AceType)
            {
                case AceType.AccessAllowed:
                case AceType.AccessAllowedObject:
                case AceType.AccessAllowedCallback:        // conditional: assume the condition holds (fail closed)
                case AceType.AccessAllowedCallbackObject:
                case AceType.AccessAllowedCompound:
                    if (ownerRights || who.MatchesAllow(sid)) { granted |= mask; decided |= mask; }
                    break;
                case AceType.AccessDenied:
                case AceType.AccessDeniedObject:
                    if (ownerRights || who.MatchesDeny(sid)) decided |= mask;
                    break;
                // AccessDeniedCallback(Object): condition unknown -> ignored (fail closed). Audit/alarm ACEs: not access.
            }
        }
        return granted & rights;
    }

    public static bool HasAny(RawSecurityDescriptor sd, PrincipalSet who, int rights) => GrantedRights(sd, who, rights) != 0;
}

/// <summary>
/// "Could the managed user have placed or replaced this exe?" (ROUND2 B.1), from the real DACLs:
/// <list type="bullet">
/// <item>the exe file: write data / append data / WRITE_DAC / WRITE_OWNER, or the user owns it;</item>
/// <item>its directory: add file / WRITE_DAC / WRITE_OWNER / owner (the user can drop or rename a file into it);</item>
/// <item>every further ancestor up to and including the volume root: WRITE_DAC / WRITE_OWNER / owner, or the
///   ancestor can be swapped out (DELETE on it or DELETE_CHILD on its parent, plus add-subdirectory on its parent).</item>
/// </list>
/// Add-subdirectory alone on an ancestor (e.g. Authenticated Users on C:\) does not make existing children writable;
/// the folder it lets the user create is owned by the user and is caught by the owner rule.
/// An unreadable security descriptor, a path that is not a drive-letter path, or a missing directory counts as
/// writable (fail closed for the managed user). Directory results are cached per (user, directory) for
/// <see cref="CacheTtl"/>; <see cref="Invalidate"/> clears the cache (policy change).
/// </summary>
public sealed class UserWritableAcl
{
    /// <summary>Reads the owner + DACL of a file or directory; null if it cannot be read.</summary>
    public delegate RawSecurityDescriptor? SecurityReader(string path, bool isDirectory);

    private const int ExeWriteRights = AclEvaluator.FileWriteData | AclEvaluator.FileAppendData
                                       | AclEvaluator.WriteDac | AclEvaluator.WriteOwner;
    private const int ParentDirRights = AclEvaluator.FileWriteData | AclEvaluator.WriteDac | AclEvaluator.WriteOwner;
    private const int AncestorRights = AclEvaluator.WriteDac | AclEvaluator.WriteOwner;
    private const int MaxEntries = 16384;

    private readonly SecurityReader _read;
    private readonly Func<long> _nowMs;
    private readonly ConcurrentDictionary<(string Sid, string Dir), (bool Writable, long At)> _dirCache = new();

    public UserWritableAcl(SecurityReader read, Func<long>? nowMs = null)
    {
        _read = read;
        _nowMs = nowMs ?? (() => Environment.TickCount64);
    }

    public TimeSpan CacheTtl { get; init; } = TimeSpan.FromMinutes(10);

    public void Invalidate() => _dirCache.Clear();

    /// <summary>True when the user (any of <paramref name="who"/>) could write, replace or re-ACL the exe.</summary>
    public bool IsUserWritable(string exePath, PrincipalSet who)
    {
        var path = NormalizeLocal(exePath);
        if (path is null) return true;

        var file = _read(path, false);
        if (file is null || IsOwner(file, who) || AclEvaluator.HasAny(file, who, ExeWriteRights)) return true;

        var dir = ParentOf(path);
        if (dir is null) return true;
        return DirectoryChainWritable(dir, who, immediateParent: true);
    }

    private bool DirectoryChainWritable(string dir, PrincipalSet who, bool immediateParent)
    {
        // The immediate parent adds "add file" on top of the ancestor rules, so cache the two flavours separately.
        var key = (who.UserSid, (immediateParent ? "P|" : "A|") + dir.ToUpperInvariant());
        long now = _nowMs();
        if (_dirCache.TryGetValue(key, out var hit) && now - hit.At < (long)CacheTtl.TotalMilliseconds) return hit.Writable;

        bool writable = ComputeDirectory(dir, who, immediateParent);
        if (_dirCache.Count > MaxEntries) _dirCache.Clear();
        _dirCache[key] = (writable, now);
        return writable;
    }

    private bool ComputeDirectory(string dir, PrincipalSet who, bool immediateParent)
    {
        var sd = _read(dir, true);
        if (sd is null) return true;
        if (IsOwner(sd, who)) return true;
        if (AclEvaluator.HasAny(sd, who, immediateParent ? ParentDirRights : AncestorRights)) return true;

        var parent = ParentOf(dir);
        if (parent is null) return false; // volume root reached and not writable

        var parentSd = _read(parent, true);
        if (parentSd is null) return true;
        bool canRemove = AclEvaluator.HasAny(sd, who, AclEvaluator.Delete)
                         || AclEvaluator.HasAny(parentSd, who, AclEvaluator.FileDeleteChild);
        if (canRemove && AclEvaluator.HasAny(parentSd, who, AclEvaluator.FileAppendData)) return true; // swap the folder

        return DirectoryChainWritable(parent, who, immediateParent: false);
    }

    private static bool IsOwner(RawSecurityDescriptor sd, PrincipalSet who)
    {
        if (sd.Owner is not { } owner || !who.MatchesAllow(owner.Value)) return false;
        // With an OWNER RIGHTS ACE the implicit owner rights are replaced by that ACE (evaluated by the walk).
        return sd.DiscretionaryAcl is not { } dacl || !dacl.Cast<GenericAce>().Any(a =>
            (a.AceFlags & AceFlags.InheritOnly) == 0 && a is KnownAce k
            && string.Equals(k.SecurityIdentifier.Value, AclEvaluator.OwnerRightsSid, StringComparison.Ordinal));
    }

    /// <summary>Drive-letter path without trailing separator, or null when the path is not a local drive path.</summary>
    internal static string? NormalizeLocal(string path)
    {
        path = PathExpander.Normalize(path);
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal) || path.StartsWith(@"\??\", StringComparison.Ordinal))
            path = path[4..];
        if (path.Length < 3 || path[1] != ':' || path[2] != '\\' || !char.IsAsciiLetter(path[0])) return null;
        if (path.Contains(@"\..\", StringComparison.Ordinal) || path.EndsWith(@"\..", StringComparison.Ordinal)) return null;
        return path.Length > 3 ? path.TrimEnd('\\') : path;
    }

    /// <summary>Parent directory ("C:\A" -> "C:\", "C:\" -> null).</summary>
    internal static string? ParentOf(string path)
    {
        if (path.Length <= 3) return null;
        int i = path.LastIndexOf('\\');
        if (i < 2) return null;
        return i == 2 ? path[..3] : path[..i];
    }
}
