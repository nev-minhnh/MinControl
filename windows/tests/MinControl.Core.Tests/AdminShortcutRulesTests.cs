using MinControl.Setup;
using Xunit;

namespace MinControl.Core.Tests;

/// <summary>"MinControl Connect" desktop shortcut / taskbar pin for the installing admin only.</summary>
public sealed class AdminShortcutRulesTests
{
    [Theory]
    [InlineData("S-1-5-21-1111111111-2222222222-3333333333-1001", true)]
    [InlineData("S-1-5-18", false)]
    [InlineData("S-1-5-21-1-2-3", false)]
    [InlineData("S-1-5-21-1-2-3-1001\" --x", false)]
    [InlineData(null, false)]
    public void Only_real_user_sids_are_accepted(string? sid, bool ok) => Assert.Equal(ok, AdminShortcutRules.IsUserSid(sid));

    [Theory]
    [InlineData(10, 19045, false)]
    [InlineData(10, 22000, true)]
    [InlineData(10, 26100, true)]
    [InlineData(6, 3, false)]
    public void Taskbar_policy_only_on_windows_11(int major, int build, bool ok) =>
        Assert.Equal(ok, AdminShortcutRules.TaskbarPolicySupported(new Version(major, 0, build)));

    [Fact]
    public void Desktop_follows_user_shell_folders()
    {
        Assert.Equal(@"C:\Users\bo\Desktop", AdminShortcutRules.DesktopOf(@"C:\Users\bo", null));
        Assert.Equal(@"C:\Users\bo\OneDrive\Desktop", AdminShortcutRules.DesktopOf(@"C:\Users\bo", @"%USERPROFILE%\OneDrive\Desktop"));
        Assert.Equal(@"D:\Desk", AdminShortcutRules.DesktopOf(@"C:\Users\bo", @"D:\Desk"));
    }

    [Fact]
    public void Foreign_start_layout_policy_is_left_alone()
    {
        const string ours = @"C:\Program Files\MinControl\TaskbarLayout.xml";
        Assert.True(AdminShortcutRules.PolicyIsFreeOrOurs(null, ours));
        Assert.True(AdminShortcutRules.PolicyIsFreeOrOurs(@"c:\program files\mincontrol\taskbarlayout.xml", ours));
        Assert.False(AdminShortcutRules.PolicyIsFreeOrOurs(@"\corp\layouts\it.xml", ours));
    }
}
