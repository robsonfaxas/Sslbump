using Sslbump.Logging;
using Sslbump.Tls.Records;

namespace Sslbump.Tls;

/// <summary>
/// A pass-through stream that sits *underneath* an <see cref="System.Net.Security.SslStream"/>
/// on the upstream (proxy -> origin) leg. Every byte read or written still goes
/// to the inner stream unchanged; a copy is fed to a per-direction record
/// reassembler so we can log the handshake steps as they happen.
///
/// Reads  = bytes coming FROM the origin  (ServerHello, Certificate, ...).
/// Writes = bytes going TO the origin     (ClientHello, ClientKeyExchange, ...).
/// The two directions are framed separately because TCP is full-duplex.
/// </summary>
public sealed class TappedStream : Stream
{
    private readonly Stream _inner;

    private readonly RecordReassembler _fromOrigin = new();
    private readonly RecordReassembler _toOrigin = new();

    public TappedStream(Stream inner, StepLogger log, Leg leg)
    {
        _inner = inner;

        // The proxy is the TLS client on this leg, so bytes we WRITE are "from the client".
        var outbound = new HandshakeTapInterpreter(log, leg, fromClient: true);
        var inbound = new HandshakeTapInterpreter(log, leg, fromClient: false);

        _toOrigin.OnRecord += outbound.Consume;
        _fromOrigin.OnRecord += inbound.Consume;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        int read = await _inner.ReadAsync(buffer, cancellationToken);
        if (read > 0)
            _fromOrigin.Feed(buffer.Span[..read]);
        return read;
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        _toOrigin.Feed(buffer.Span);
        await _inner.WriteAsync(buffer, cancellationToken);
    }

    // SslStream uses the span/memory async overloads above; the rest just forward.
    public override int Read(byte[] buffer, int offset, int count)
    {
        int read = _inner.Read(buffer, offset, count);
        if (read > 0)
            _fromOrigin.Feed(buffer.AsSpan(offset, read));
        return read;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        _toOrigin.Feed(buffer.AsSpan(offset, count));
        _inner.Write(buffer, offset, count);
    }

    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override bool CanRead => _inner.CanRead;
    public override bool CanWrite => _inner.CanWrite;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _inner.Dispose();
        base.Dispose(disposing);
    }
}
