using Microsoft.Extensions.Logging;

namespace MinControl.Core.Diagnostics;

public sealed record LogLine(DateTimeOffset At, LogLevel Level, string Category, string Message);

/// <summary>
/// In-memory ring of recent log lines for <c>diag.report</c> (API.md §14): the last <see cref="Capacity"/> warning/error
/// lines of every category, and the last <see cref="Capacity"/> Information lines of MinControl's own components
/// (enforcement decisions: proxy summaries, WFP apply results, app blocks…). Messages are scrubbed on entry.
/// </summary>
public sealed class LogRing
{
    public const int Capacity = 200;
    public const int MaxMessageChars = 1000;

    private readonly Queue<LogLine> _problems = new();
    private readonly Queue<LogLine> _decisions = new();
    private readonly object _gate = new();

    public void Add(LogLine line)
    {
        var msg = SecretScrubber.Scrub(line.Message);
        if (msg.Length > MaxMessageChars) msg = msg[..MaxMessageChars] + "…";
        line = line with { Message = msg };
        lock (_gate)
        {
            var q = line.Level >= LogLevel.Warning ? _problems : _decisions;
            q.Enqueue(line);
            while (q.Count > Capacity) q.Dequeue();
        }
    }

    public IReadOnlyList<LogLine> Problems() { lock (_gate) return _problems.ToArray(); }

    public IReadOnlyList<LogLine> Decisions() { lock (_gate) return _decisions.ToArray(); }
}

/// <summary>Feeds <see cref="LogRing"/>. Registered as an <see cref="ILoggerProvider"/> in the service container.</summary>
public sealed class RingBufferLoggerProvider(LogRing ring, Func<DateTimeOffset>? now = null) : ILoggerProvider
{
    private readonly Func<DateTimeOffset> _now = now ?? (() => DateTimeOffset.UtcNow);

    public ILogger CreateLogger(string categoryName) => new RingLogger(ring, categoryName, _now);

    public void Dispose() { }

    private sealed class RingLogger(LogRing ring, string category, Func<DateTimeOffset> now) : ILogger
    {
        private readonly bool _ours = category.StartsWith("MinControl.", StringComparison.Ordinal);

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) =>
            logLevel != LogLevel.None && (logLevel >= LogLevel.Warning || (_ours && logLevel == LogLevel.Information));

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            string msg;
            try { msg = formatter(state, exception); }
            catch { msg = state?.ToString() ?? ""; }
            if (exception is not null) msg += $" | {exception.GetType().Name}: {exception.Message}";
            var shortCategory = category.StartsWith("MinControl.", StringComparison.Ordinal) ? category["MinControl.".Length..] : category;
            ring.Add(new LogLine(now(), logLevel, shortCategory, msg));
        }
    }
}
