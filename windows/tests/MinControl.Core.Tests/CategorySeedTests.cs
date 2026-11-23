using System.IO.Compression;
using System.Text;
using System.Text.Json.Nodes;
using MinControl.CategorySeed;
using MinControl.Core.Catalog;
using MinControl.NetGuard.Categories;
using MinControl.NetGuard.Web;
using Xunit;

namespace MinControl.Core.Tests;

public sealed class CategorySeedTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "mc-seed-" + Guid.NewGuid().ToString("N"));

    public CategorySeedTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private string MakeZip(params (string Name, string Content)[] entries)
    {
        var path = Path.Combine(_dir, "ut1.zip");
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (name, content) in entries)
        {
            var e = zip.CreateEntry(name);
            using var w = new StreamWriter(e.Open(), new UTF8Encoding(false));
            w.Write(content);
        }
        return path;
    }

    [Fact]
    public async Task Seed_unions_catalog_domains_into_the_first_list_and_writes_state()
    {
        var firstVideo = Ut1Catalog.Sources["video"][0];
        var zip = MakeZip(($"ut1-master/blacklists/{firstVideo}/domains", "example-video.test\n# c\n10.0.0.1\nclips.test\n"));
        var outDir = Path.Combine(_dir, "out");

        var result = await CategorySeedBuilder.BuildAsync(zip, outDir, ServiceCatalog.Shared, ["video"]);

        Assert.Single(result.Built);
        var file = Ut1Catalog.FileName("video", firstVideo);
        var set = HashedDomainSet.Read(Path.Combine(outDir, file));
        Assert.True(set.MatchesHostOrParent("sub.example-video.test"));   // from the list
        Assert.True(set.MatchesHostOrParent("m.youtube.com"));            // from the curated catalog
        Assert.False(set.MatchesHostOrParent("10.0.0.1"));

        var state = JsonNode.Parse(File.ReadAllText(Path.Combine(outDir, CategorySeedBuilder.StateFileName)))!.AsObject();
        var entry = state[file]!.AsObject();
        Assert.Equal(set.Count, (int)entry["Domains"]!);
        Assert.Null(entry["ETag"]);
        Assert.NotNull(entry["LastModified"]);
        Assert.NotNull(entry["UpdatedUtc"]);
    }

    [Fact]
    public async Task Split_lists_are_concatenated_even_when_the_split_is_mid_line()
    {
        var list = Ut1Catalog.Sources["adult"][0];
        var zip = MakeZip(
            ($"r/blacklists/{list}/domains.0", "aaa-one.test\nbbb-tw"),
            ($"r/blacklists/{list}/domains.1", "o.test\nccc-three.test\n"));
        var outDir = Path.Combine(_dir, "out");

        var result = await CategorySeedBuilder.BuildAsync(zip, outDir, ServiceCatalog.Shared, ["adult"]);

        Assert.Contains($"adult/{list}", result.Built);
        var set = HashedDomainSet.Read(Path.Combine(outDir, Ut1Catalog.FileName("adult", list)));
        Assert.True(set.MatchesHostOrParent("bbb-two.test"));
        Assert.False(set.MatchesHostOrParent("bbb-tw.test"));
        Assert.True(set.MatchesHostOrParent("ccc-three.test"));
    }

    [Fact]
    public async Task Missing_lists_fail_individually_and_nothing_built_writes_no_state()
    {
        var zip = MakeZip(("r/blacklists/unrelated/domains", "x.test\n"));
        var outDir = Path.Combine(_dir, "out");
        var result = await CategorySeedBuilder.BuildAsync(zip, outDir, ServiceCatalog.Shared, ["dating"]);
        Assert.Empty(result.Built);
        Assert.NotEmpty(result.Failed);
        Assert.False(File.Exists(Path.Combine(outDir, CategorySeedBuilder.StateFileName)));
    }
}
