namespace MinControl.Monitoring.Rules;

/// <summary>
/// Recognises web browsers by executable. Only genuine Edge / Chrome (by Authenticode publisher) can be
/// allowed through <c>web.allowedBrowsers</c>; every other browser - including Chromium builds and
/// portable forks that ship a <c>chrome.exe</c> - is blocked so the extension + proxy cannot be bypassed.
/// </summary>
public static class KnownBrowsers
{
    public const string EdgeExe = "msedge.exe";
    public const string ChromeExe = "chrome.exe";

    private static readonly Dictionary<string, string> GenuinePublishers = new(StringComparer.OrdinalIgnoreCase)
    {
        [EdgeExe] = "Microsoft Corporation",
        [ChromeExe] = "Google LLC",
    };

    /// <summary>Executable names that are always a browser (or a browser's network engine).</summary>
    private static readonly HashSet<string> BrowserExes = new(StringComparer.OrdinalIgnoreCase)
    {
        EdgeExe, ChromeExe,
        "firefox.exe", "waterfox.exe", "librewolf.exe", "palemoon.exe", "basilisk.exe", "seamonkey.exe",
        "floorp.exe", "zen.exe", "mullvadbrowser.exe", "tor.exe", "torbrowser.exe",
        "opera.exe", "opera_gx.exe",
        "brave.exe", "vivaldi.exe", "thorium.exe", "supermium.exe", "chromium.exe", "iridium.exe",
        "yandex.exe", "coccoc.exe", "maxthon.exe", "ucbrowser.exe", "360se.exe", "360chrome.exe",
        "qqbrowser.exe", "sogouexplorer.exe", "slimjet.exe", "dragon.exe", "torch.exe", "epic.exe",
        "avastbrowser.exe", "avgbrowser.exe", "ccleanerbrowser.exe", "duckduckgo.exe", "arc.exe",
        "msedgecanary.exe", "iexplore.exe", "falkon.exe", "midori.exe", "k-meleon.exe", "otter-browser.exe",
        "srware iron.exe", "iron.exe", "comodo dragon.exe", "centbrowser.exe", "ghostery.exe",
        "whale.exe", "naver whale.exe", "sidekick.exe", "wavebox.exe",
    };

    /// <summary>Generic exe names that are a browser only in a vendor folder.</summary>
    private static readonly (string Exe, string PathFragment)[] PathScoped =
    [
        ("browser.exe", @"\Yandex\"),
        ("browser.exe", @"\CocCoc\"),
        ("browser.exe", @"\Coc Coc\"),
        ("browser.exe", @"\Cốc Cốc\"),
        ("launcher.exe", @"\Opera"),
    ];

    public enum Kind { NotBrowser, GenuineAllowedCandidate, Other }

    /// <summary>
    /// Classifies <paramref name="exePath"/>. Returns the canonical allowed-browser name (msedge.exe /
    /// chrome.exe) in <paramref name="canonical"/> when it is a genuine, signed build of one of those.
    /// </summary>
    public static Kind Classify(string exePath, IFileFacts facts, out string? canonical)
    {
        canonical = null;
        string exe = Path.GetFileName(exePath);

        bool isBrowser = BrowserExes.Contains(exe);
        if (!isBrowser)
        {
            foreach (var (name, frag) in PathScoped)
            {
                if (exe.Equals(name, StringComparison.OrdinalIgnoreCase)
                    && exePath.Contains(frag, StringComparison.OrdinalIgnoreCase))
                {
                    isBrowser = true;
                    break;
                }
            }
        }
        if (!isBrowser) return Kind.NotBrowser;

        if (GenuinePublishers.TryGetValue(exe, out var publisher))
        {
            var sig = facts.Signature(exePath);
            if (sig.Signed && string.Equals(sig.Publisher, publisher, StringComparison.OrdinalIgnoreCase))
            {
                canonical = exe.ToLowerInvariant();
                return Kind.GenuineAllowedCandidate;
            }
        }
        return Kind.Other; // includes unsigned/foreign chrome.exe (Chromium portable, Cent, ungoogled...)
    }
}
