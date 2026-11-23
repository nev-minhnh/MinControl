namespace MinControl.NetGuard.Categories;

/// <summary>Read-only, forward-only stream over several files in order (the GitHub mirror's split <c>domains.0..N</c>:
/// the split is byte-wise and may cut a line, so the parts must be read as one stream).</summary>
public sealed class ConcatenatedFileStream(IReadOnlyList<string> paths) : Stream
{
    private int _index = -1;
    private FileStream? _current;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        while (true)
        {
            if (_current is null && !Next()) return 0;
            var n = _current!.Read(buffer);
            if (n > 0) return n;
            _current.Dispose();
            _current = null;
        }
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (true)
        {
            if (_current is null && !Next()) return 0;
            var n = await _current!.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (n > 0) return n;
            await _current.DisposeAsync().ConfigureAwait(false);
            _current = null;
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    private bool Next()
    {
        if (++_index >= paths.Count) return false;
        _current = new FileStream(paths[_index], FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, useAsync: true);
        return true;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _current?.Dispose();
        _current = null;
        base.Dispose(disposing);
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
