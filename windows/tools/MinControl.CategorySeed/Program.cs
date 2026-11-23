using MinControl.CategorySeed;
using MinControl.Core.Catalog;

// MinControl.CategorySeed --out <dir> [--zip <ut1-blacklists-master.zip>] [--only cat1,cat2]
// Build-time only (scripts/build-msi.ps1). No network. Exit code: 0 = at least one list built, 1 = nothing built, 2 = usage.
string? Opt(string name) { var i = Array.IndexOf(args, name); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }

var outDir = Opt("--out");
if (outDir is null)
{
    Console.Error.WriteLine("usage: MinControl.CategorySeed --out <dir> [--zip <zip>] [--only cat1,cat2]");
    return 2;
}
var zip = Opt("--zip") ?? @"D:\Coding_Project\MinControl\tools\ut1\ut1-blacklists-master.zip";
if (!File.Exists(zip)) { Console.Error.WriteLine($"UT1 snapshot not found: {zip}"); return 1; }
var only = Opt("--only")?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
var result = await CategorySeedBuilder.BuildAsync(zip, outDir, ServiceCatalog.Shared, only, Console.WriteLine);
Console.WriteLine($"seed: {result.Built.Count} built, {result.Failed.Count} failed -> {outDir}");
foreach (var w in result.Warnings) Console.Error.WriteLine("warning: " + w);
return result.Built.Count > 0 ? 0 : 1;
