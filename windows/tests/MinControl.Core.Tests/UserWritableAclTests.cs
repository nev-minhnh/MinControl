using System.Security.AccessControl;
using MinControl.Core.Policy;
using MinControl.Monitoring.Rules;
using Xunit;

namespace MinControl.Core.Tests;

// ROUND2 B.1: user-writable detection from DACLs (pure ACE walk on synthetic security descriptors, no file system).
public class UserWritableAclTests
{
    private const string Kid = "S-1-5-21-1000-2000-3000-1001";
    private const string Other = "S-1-5-21-1000-2000-3000-1002";
    private const string CustomGroup = "S-1-5-21-1000-2000-3000-1500";

    private static readonly PrincipalSet KidToken = PrincipalSet.Fallback(Kid);

    // FILE_GENERIC_READ|EXECUTE, Modify, Full
    private const string RX = "0x1200a9";
    private const string Modify = "0x1301bf";

    private static RawSecurityDescriptor Sd(string sddl) => new(sddl);

    private static int Granted(string sddl, PrincipalSet? who = null, int rights = AclEvaluator.FileWriteData)
        => AclEvaluator.GrantedRights(Sd(sddl), who ?? KidToken, rights);

    // ------------------------------------------------------------------ ACE walk

    [Fact]
    public void Program_files_style_acl_is_not_writable() =>
        Assert.Equal(0, Granted($"O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;{RX};;;BU)(A;OICIIO;GA;;;CO)",
            rights: AclEvaluator.FileWriteData | AclEvaluator.FileAppendData | AclEvaluator.WriteDac | AclEvaluator.WriteOwner | AclEvaluator.Delete));

    [Fact]
    public void Authenticated_users_modify_grants_write() =>
        Assert.NotEqual(0, Granted($"O:BAG:SYD:(A;;FA;;;SY)(A;;{Modify};;;AU)"));

    [Fact]
    public void Users_group_and_everyone_are_matched_through_the_token() =>
        Assert.NotEqual(0, Granted("O:BAG:SYD:(A;;0x2;;;WD)") & Granted("O:BAG:SYD:(A;;0x2;;;BU)") & Granted("O:BAG:SYD:(A;;0x2;;;IU)"));

    [Fact]
    public void Unrelated_sid_grant_is_ignored() =>
        Assert.Equal(0, Granted($"O:BAG:SYD:(A;;FA;;;{Other})(A;;FA;;;BA)"));

    [Fact]
    public void Deny_ace_before_allow_wins() =>
        Assert.Equal(0, Granted($"O:BAG:SYD:(D;;0x6;;;WD)(A;;{Modify};;;AU)", rights: AclEvaluator.FileWriteData | AclEvaluator.FileAppendData));

    [Fact]
    public void Deny_of_one_bit_leaves_the_others()
    {
        int g = Granted($"O:BAG:SYD:(D;;0x2;;;{Kid})(A;;{Modify};;;AU)", rights: AclEvaluator.FileWriteData | AclEvaluator.FileAppendData);
        Assert.Equal(AclEvaluator.FileAppendData, g);
    }

    [Fact]
    public void Non_canonical_allow_before_deny_grants() =>
        // AccessCheck walks the ACL in stored order: the earlier allow decides the bit.
        Assert.NotEqual(0, Granted($"O:BAG:SYD:(A;;0x2;;;{Kid})(D;;0x2;;;WD)"));

    [Fact]
    public void Inherit_only_aces_do_not_apply_to_the_object_itself() =>
        Assert.Equal(0, Granted($"O:BAG:SYD:(A;OICIIO;{Modify};;;AU)(A;;{RX};;;BU)"));

    [Fact]
    public void Generic_write_and_generic_all_are_mapped() =>
        Assert.True(Granted("O:BAG:SYD:(A;;GW;;;BU)") != 0 && Granted("O:BAG:SYD:(A;;GA;;;BU)") != 0);

    [Fact]
    public void Null_dacl_grants_everything() =>
        Assert.Equal(AclEvaluator.FileWriteData, Granted("O:BAG:SYD:NO_ACCESS_CONTROL"));

    [Fact]
    public void Owner_gets_write_dac_implicitly()
    {
        Assert.Equal(AclEvaluator.WriteDac, Granted($"O:{Kid}G:SYD:(A;;{RX};;;BU)", rights: AclEvaluator.WriteDac));
        // ... even when a deny ACE would otherwise deny it (implicit owner rights precede the walk)
        Assert.Equal(AclEvaluator.WriteDac, Granted($"O:{Kid}G:SYD:(D;;WD;;;WD)", rights: AclEvaluator.WriteDac));
    }

    [Fact]
    public void Owner_rights_ace_replaces_implicit_owner_rights()
    {
        Assert.Equal(0, Granted($"O:{Kid}G:SYD:(A;;{RX};;;OW)", rights: AclEvaluator.WriteDac | AclEvaluator.FileWriteData));
        Assert.Equal(AclEvaluator.FileWriteData, Granted($"O:{Kid}G:SYD:(A;;0x2;;;OW)", rights: AclEvaluator.WriteDac | AclEvaluator.FileWriteData));
        // OWNER RIGHTS does not apply to someone who is not the owner
        Assert.Equal(0, Granted("O:BAG:SYD:(A;;FA;;;OW)"));
    }

    [Fact]
    public void Deny_only_group_matches_deny_but_not_allow()
    {
        var token = new PrincipalSet(Kid, ["S-1-5-11", "S-1-1-0"], denyOnly: [CustomGroup]);
        Assert.Equal(0, Granted($"O:BAG:SYD:(A;;FA;;;{CustomGroup})", token));
        Assert.Equal(0, Granted($"O:BAG:SYD:(D;;0x2;;;{CustomGroup})(A;;FA;;;AU)", token));
        Assert.NotEqual(0, Granted("O:BAG:SYD:(A;;FA;;;AU)", token));
    }

    [Fact]
    public void Real_token_groups_are_honoured()
    {
        var token = new PrincipalSet(Kid, [.. PrincipalSet.WellKnownInteractiveGroups, CustomGroup]);
        Assert.NotEqual(0, Granted($"O:BAG:SYD:(A;;0x2;;;{CustomGroup})", token));
        Assert.Equal(0, Granted($"O:BAG:SYD:(A;;0x2;;;{CustomGroup})"));
    }

    [Fact]
    public void Conditional_allow_counts_as_allow_and_conditional_deny_is_ignored()
    {
        Assert.NotEqual(0, Granted("O:BAG:SYD:(XA;;0x2;;;WD;(@User.Title == \"PM\"))"));
        Assert.NotEqual(0, Granted("O:BAG:SYD:(XD;;0x2;;;WD;(@User.Title == \"PM\"))(A;;0x2;;;WD)"));
    }

    // ------------------------------------------------------------------ chain (file + parents up to the volume root)

    private const string Root = "O:SYG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;" + RX + ";;;BU)(A;OICIIO;" + Modify + ";;;AU)(A;;0x4;;;AU)";
    private const string Locked = "O:S-1-5-80-1G:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;" + RX + ";;;BU)";
    private const string AuModify = "O:BAG:SYD:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;" + RX + ";;;BU)(A;OICIID;" + Modify + ";;;AU)";
    private const string KidOwned = "O:" + Kid + "G:SYD:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;" + RX + ";;;BU)";
    private const string ProgramDataLike = "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;" + RX + ";;;BU)(A;CI;0x116;;;BU)";
    private const string LockedFile = "O:BAG:SYD:PAI(A;;FA;;;BA)(A;;FA;;;SY)(A;;" + RX + ";;;BU)";

    private static UserWritableAcl Chain(Dictionary<string, string> sddl, long now = 0)
        => new((path, _) => sddl.TryGetValue(path, out var s) ? new RawSecurityDescriptor(s) : null, () => now);

    private static Dictionary<string, string> Drive(params (string Path, string Sddl)[] extra)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [@"C:\"] = Root,
            [@"C:\Program Files"] = Locked,
            [@"C:\Program Files\App"] = Locked,
            [@"C:\Program Files\App\app.exe"] = LockedFile,
        };
        foreach (var (p, s) in extra) d[p] = s;
        return d;
    }

    [Fact]
    public void Exe_in_program_files_is_not_user_writable() =>
        Assert.False(Chain(Drive()).IsUserWritable(@"C:\Program Files\App\app.exe", KidToken));

    [Fact]
    public void Add_subdirectory_on_the_volume_root_alone_does_not_make_children_writable() =>
        // Authenticated Users have FILE_ADD_SUBDIRECTORY on C:\ by default.
        Assert.False(Chain(Drive()).IsUserWritable(@"C:\Program Files\App\app.exe", KidToken));

    [Fact]
    public void Folder_the_kid_created_under_c_is_user_writable() =>
        Assert.True(Chain(Drive((@"C:\Games", KidOwned), (@"C:\Games\game.exe", KidOwned)))
            .IsUserWritable(@"C:\Games\game.exe", KidToken));

    [Fact]
    public void Kid_owned_exe_in_a_locked_folder_is_user_writable() =>
        Assert.True(Chain(Drive((@"C:\Program Files\App\x.exe", "O:" + Kid + "G:SYD:(A;;" + RX + ";;;BU)")))
            .IsUserWritable(@"C:\Program Files\App\x.exe", KidToken));

    [Fact]
    public void Admin_created_folder_inheriting_authenticated_users_modify_is_user_writable() =>
        Assert.True(Chain(Drive((@"C:\Tools", AuModify), (@"C:\Tools\t.exe", LockedFile)))
            .IsUserWritable(@"C:\Tools\t.exe", KidToken));

    [Fact]
    public void Writable_exe_file_in_locked_folder_is_user_writable() =>
        Assert.True(Chain(Drive((@"C:\Program Files\App\w.exe", "O:BAG:SYD:(A;;" + Modify + ";;;BU)")))
            .IsUserWritable(@"C:\Program Files\App\w.exe", KidToken));

    [Fact]
    public void Add_file_on_the_parent_folder_is_user_writable() =>
        Assert.True(Chain(Drive((@"C:\ProgramData", ProgramDataLike), (@"C:\ProgramData\x.exe", LockedFile)))
            .IsUserWritable(@"C:\ProgramData\x.exe", KidToken));

    [Fact]
    public void Protected_subfolder_of_a_user_writable_folder_is_not_writable() =>
        Assert.False(Chain(Drive((@"C:\ProgramData", ProgramDataLike), (@"C:\ProgramData\Vendor", Locked),
                (@"C:\ProgramData\Vendor\v.exe", LockedFile)))
            .IsUserWritable(@"C:\ProgramData\Vendor\v.exe", KidToken));

    [Fact]
    public void Write_dac_on_any_ancestor_is_user_writable() =>
        Assert.True(Chain(Drive((@"C:\Program Files", "O:S-1-5-80-1G:SYD:PAI(A;;FA;;;SY)(A;;" + RX + ";;;BU)(A;;WD;;;IU)")))
            .IsUserWritable(@"C:\Program Files\App\app.exe", KidToken));

    [Fact]
    public void Ancestor_that_can_be_renamed_and_recreated_is_user_writable() =>
        // DELETE on C:\Opt\Pkg + add-subdirectory on C:\Opt: rename Pkg away and create a new one.
        Assert.True(Chain(Drive((@"C:\Opt", "O:SYG:SYD:PAI(A;;FA;;;SY)(A;;" + RX + ";;;BU)(A;;0x4;;;BU)"),
                (@"C:\Opt\Pkg", "O:SYG:SYD:PAI(A;;FA;;;SY)(A;;" + RX + ";;;BU)(A;;SD;;;BU)"),
                (@"C:\Opt\Pkg\p.exe", LockedFile)))
            .IsUserWritable(@"C:\Opt\Pkg\p.exe", KidToken));

    [Fact]
    public void Unreadable_security_descriptor_fails_closed() =>
        // the kid removed SYSTEM from the folder ACL: the service cannot read it -> treated as writable
        Assert.True(Chain(Drive((@"C:\Hidden\h.exe", LockedFile))).IsUserWritable(@"C:\Hidden\h.exe", KidToken));

    [Theory]
    [InlineData(@"\Device\HarddiskVolume9\x.exe")]
    [InlineData(@"relative\x.exe")]
    [InlineData(@"C:\Program Files\App\..\..\Games\x.exe")]
    public void Non_local_or_odd_paths_fail_closed(string path) =>
        Assert.True(Chain(Drive()).IsUserWritable(path, KidToken));

    [Fact]
    public void Extended_length_prefix_is_accepted() =>
        Assert.False(Chain(Drive()).IsUserWritable(@"\\?\C:\Program Files\App\app.exe", KidToken));

    [Fact]
    public void Directory_verdicts_are_cached_until_ttl_or_invalidate()
    {
        var map = Drive((@"C:\Tools", Locked), (@"C:\Tools\t.exe", LockedFile));
        long now = 0;
        var acl = new UserWritableAcl((p, _) => map.TryGetValue(p, out var s) ? new RawSecurityDescriptor(s) : null, () => now);
        Assert.False(acl.IsUserWritable(@"C:\Tools\t.exe", KidToken));

        map[@"C:\Tools"] = AuModify;                     // ACL changed behind our back
        Assert.False(acl.IsUserWritable(@"C:\Tools\t.exe", KidToken));   // cached
        now += (long)TimeSpan.FromMinutes(11).TotalMilliseconds;
        Assert.True(acl.IsUserWritable(@"C:\Tools\t.exe", KidToken));    // expired

        map[@"C:\Tools"] = Locked;
        acl.Invalidate();
        Assert.False(acl.IsUserWritable(@"C:\Tools\t.exe", KidToken));
    }

    // ------------------------------------------------------------------ evaluator wiring

    private static UserPolicy Policy(string newExecutable) => new(
        "Bin",
        new ScreenTimePolicy(new WeekdayMap<int>(120, 120, 120, 120, 120, 120, 120),
            new WeekdayMap<IReadOnlyList<string>>(["00:00-24:00"], ["00:00-24:00"], ["00:00-24:00"], ["00:00-24:00"],
                ["00:00-24:00"], ["00:00-24:00"], ["00:00-24:00"]), [5], 60, false, 300),
        new Dictionary<string, AppGroup>(), [], newExecutable,
        new WebPolicy("blocklist", [], [], [], true, "strict", ["msedge.exe", "chrome.exe"], []),
        new MonitoringPolicy(true, true, true, true, true, new ScreenshotPolicy(5, true, 1280, 60)));

    private sealed class NoFacts : IFileFacts
    {
        public string? Sha256(string path) => null;
        public SignatureInfo Signature(string path) => SignatureInfo.Unsigned;
        public long? SizeBytes(string path) => null;
    }

    private static EvaluationContext Ctx(Func<string, bool>? acl) => new()
    {
        Sid = Kid,
        ProfilePath = @"C:\Users\bin",
        ExtraUserWritableRoots = [@"C:\Windows\Temp"],
        WindowsDir = @"C:\Windows",
        IsUserWritableByAcl = acl,
    };

    [Fact]
    public void Acl_writable_exe_outside_profile_goes_through_newExecutable()
    {
        var ev = new AppRuleEvaluator(new NoFacts());
        var d = ev.Evaluate(Policy("block"), @"C:\Games\game.exe", Ctx(p => p.StartsWith(@"C:\Games\", StringComparison.OrdinalIgnoreCase)));
        Assert.Equal(Verdict.Block, d.Verdict);
        Assert.Equal("newExecutable", d.Rule);
        Assert.Equal(Verdict.Allow, ev.Evaluate(Policy("block"), @"C:\Program Files\App\app.exe", Ctx(_ => false)).Verdict);
    }

    [Fact]
    public void Profile_fast_path_does_not_need_the_acl_check()
    {
        bool called = false;
        var d = new AppRuleEvaluator(new NoFacts()).Evaluate(Policy("block"), @"C:\Users\bin\Downloads\x.exe",
            Ctx(_ => { called = true; return false; }));
        Assert.Equal("newExecutable", d.Rule);
        Assert.False(called);
    }

    [Theory]
    [InlineData(@"C:\Windows\explorer.exe", true)]
    [InlineData(@"C:\Windows\System32\sihost.exe", true)]
    [InlineData(@"C:\Windows\SysWOW64\rundll32.exe", true)]
    [InlineData(@"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe", true)]
    [InlineData(@"C:\Windows\Tasks\explorer.exe", false)]                          // user-writable folder under %windir%
    [InlineData(@"C:\Windows\System32\spool\drivers\color\explorer.exe", false)]   // user-writable folder under System32
    [InlineData(@"C:\Windows\Temp\explorer.exe", false)]
    [InlineData(@"C:\Users\bin\explorer.exe", false)]
    public void Critical_shell_protection_only_in_fixed_windows_folders(string path, bool critical) =>
        Assert.Equal(critical, AppRuleEvaluator.IsCriticalShell(path, Ctx(null)));
}
