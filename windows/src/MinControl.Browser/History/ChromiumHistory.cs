using System.Globalization;
using Microsoft.Data.Sqlite;

namespace MinControl.Browser.History;

/// <summary>One row of <c>visits JOIN urls</c> (+ the search term typed for that url, if any).</summary>
public sealed record HistoryVisit(long Id, string Url, string? Title, long VisitTime, long DurationUs, long Transition, string? SearchTerm);

/// <summary>Result of one bounded read: visits with id &gt; cursor (ordered by id), the highest id scanned and MAX(visits.id).</summary>
public sealed record HistoryReadResult(IReadOnlyList<HistoryVisit> Visits, long LastScannedId, long MaxVisitId, bool Truncated);

/// <summary>Pure helpers + the SQL for Chromium's History database (Edge and Chrome share the schema).</summary>
public static class ChromiumHistory
{
    private static readonly DateTimeOffset WebKitEpoch = new(1601, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private const long MaxWebKitUs = (long)((9999L - 1601L) * 365.2425 * 86_400 * 1_000_000);

    /// <summary>WebKit time (µs since 1601-01-01 UTC) → UTC; null for 0/negative/out-of-range values.</summary>
    public static DateTimeOffset? FromWebKit(long us) =>
        us <= 0 || us >= MaxWebKitUs ? null : WebKitEpoch.AddTicks(us * 10);

    public static long ToWebKit(DateTimeOffset t) => (t.UtcTicks - WebKitEpoch.UtcTicks) / 10;

    /// <summary>Core transition (<c>transition &amp; 0xFF</c>, ui::PageTransition) → schema string.</summary>
    public static string TransitionName(long transition) => (transition & 0xFF) switch
    {
        0 => "link",
        1 => "typed",
        2 => "auto_bookmark",
        3 => "auto_subframe",
        4 => "manual_subframe",
        5 => "generated",
        6 => "auto_toplevel",
        7 => "form_submit",
        8 => "reload",
        9 => "keyword",
        10 => "keyword_generated",
        _ => "other",
    };

    /// <summary>Search engine of a search-results URL by host: google | bing | youtube | coccoc | other.</summary>
    public static string SearchEngine(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return "other";
        string host = uri.Host.ToLowerInvariant();
        if (HostIs(host, "youtube.com") || HostIs(host, "youtu.be")) return "youtube";
        if (HostIs(host, "bing.com")) return "bing";
        if (HostIs(host, "coccoc.com")) return "coccoc";
        // google.com, google.com.vn, google.co.uk, www.google.de, …
        string[] labels = host.Split('.');
        int g = Array.IndexOf(labels, "google");
        if (g >= 0 && g >= labels.Length - 3 && g < labels.Length - 1 && labels.Skip(g + 1).All(l => l.Length is >= 2 and <= 3))
            return "google";
        return "other";
    }

    private static bool HostIs(string host, string domain) =>
        host == domain || host.EndsWith("." + domain, StringComparison.Ordinal);

    public static bool IsHttp(string url) =>
        url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || url.StartsWith("https://", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Reads at most <paramref name="limit"/> visits with <c>id &gt; afterId</c> and <c>visit_time &gt;= minVisitTime</c>
    /// (WebKit µs), ordered by id. When fewer than <paramref name="limit"/> rows match, the cursor moves to MAX(id),
    /// so older rows filtered out by time are skipped for good (Chromium indexes visit_time).
    /// </summary>
    public static HistoryReadResult Read(string dbPath, long afterId, long minVisitTime, int limit, bool readWrite = false)
    {
        var csb = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = readWrite ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadOnly,
            Pooling = false,                 // the temp copy is deleted right after
        };
        using var db = new SqliteConnection(csb.ToString());
        db.Open();
        long maxId;
        using (var cmd = db.CreateCommand())
        {
            cmd.CommandText = "SELECT IFNULL(MAX(id), 0) FROM visits";
            maxId = Convert.ToInt64(cmd.ExecuteScalar(), CultureInfo.InvariantCulture);
        }
        bool hasTerms;
        using (var cmd = db.CreateCommand())
        {
            cmd.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='keyword_search_terms'";
            hasTerms = Convert.ToInt64(cmd.ExecuteScalar(), CultureInfo.InvariantCulture) > 0;
        }

        var list = new List<HistoryVisit>();
        long last = afterId;
        int scanned = 0;
        using (var cmd = db.CreateCommand())
        {
            string term = hasTerms ? "(SELECT k.term FROM keyword_search_terms k WHERE k.url_id = u.id LIMIT 1)" : "NULL";
            cmd.CommandText =
                $"SELECT v.id, u.url, u.title, v.visit_time, v.visit_duration, v.transition, {term} " +
                "FROM visits v JOIN urls u ON u.id = v.url WHERE v.id > $after AND v.visit_time >= $min ORDER BY v.id LIMIT $limit";
            cmd.Parameters.AddWithValue("$after", afterId);
            cmd.Parameters.AddWithValue("$min", minVisitTime);
            cmd.Parameters.AddWithValue("$limit", limit);
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                scanned++;
                long id = r.GetInt64(0);
                last = id;
                long time = r.IsDBNull(3) ? 0 : r.GetInt64(3);
                if (time < minVisitTime) continue;
                list.Add(new HistoryVisit(id, r.IsDBNull(1) ? "" : r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2), time,
                    r.IsDBNull(4) ? 0 : r.GetInt64(4), r.IsDBNull(5) ? 0 : r.GetInt64(5), r.IsDBNull(6) ? null : r.GetString(6)));
            }
        }
        bool truncated = scanned >= limit;
        // Not truncated: everything up to MAX(id) was seen (visits whose url row is missing are skipped for good).
        if (!truncated && maxId > last) last = maxId;
        return new HistoryReadResult(list, last, maxId, truncated);
    }
}
