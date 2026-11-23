using MinControl.Setup;
using Xunit;

namespace MinControl.Core.Tests;

public sealed class SetupWipeTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "mc-wipe-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void Fresh_install_wipe_removes_everything_but_categories()
    {
        Directory.CreateDirectory(Path.Combine(_root, "categories", "seed"));
        Directory.CreateDirectory(Path.Combine(_root, "screens", "a"));
        Directory.CreateDirectory(Path.Combine(_root, "logs"));
        foreach (var f in new[] { "state.db", "device.key", "config.json", "enroll-status.json", "expected-stop.json",
                     Path.Combine("screens", "a", "1.jpg"), Path.Combine("logs", "x.log"), Path.Combine("categories", "adult.bin"),
                     Path.Combine("categories", ".ut1-state.json"), Path.Combine("categories", "seed", "video.bin") })
            File.WriteAllText(Path.Combine(_root, f), "x");

        var failed = SetupWipe.WipeExceptCategories(_root);

        Assert.Empty(failed);
        Assert.Equal("categories", Assert.Single(Directory.GetFileSystemEntries(_root).Select(Path.GetFileName)));
        Assert.True(File.Exists(Path.Combine(_root, "categories", "adult.bin")));
        Assert.True(File.Exists(Path.Combine(_root, "categories", "seed", "video.bin")));
        Assert.True(File.Exists(Path.Combine(_root, "categories", ".ut1-state.json")));
    }

    [Fact]
    public void Wipe_of_a_missing_root_is_a_noop()
    {
        Assert.Empty(SetupWipe.WipeExceptCategories(_root));
        Assert.False(Directory.Exists(_root));
    }
}
