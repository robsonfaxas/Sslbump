using Sslbump.Tls.Records;

namespace Sslbump.Tls.Server;

/// <summary>
/// An established TLS 1.2 connection on the browser leg, exposed as a plain
/// <see cref="Stream"/> so the HTTP relay can treat it like any other socket.
/// Reads pull encrypted application-data records and decrypt them; writes encrypt
/// plaintext into application-data records. The handshake is already finished by
/// the time this object exists.
/// </summary>
public sealed class TlsServerConnection : Stream
{
    private const int MaxPlaintextPerRecord = 16384;

    private readonly RecordChannel _channel;
    private readonly GcmRecordLayer _decrypt; // client -> server
    private readonly GcmRecordLayer _encrypt; // server -> client

    private byte[] _leftover = [];
    private int _leftoverOffset;
    private bool _closed;

    public TlsServerConnection(RecordChannel channel, GcmRecordLayer decrypt, GcmRecordLayer encrypt)
    {
        _channel = channel;
        _decrypt = decrypt;
        _encrypt = encrypt;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        // Serve whatever is left from the previously decrypted record first.
        if (_leftoverOffset < _leftover.Length)
            return CopyLeftover(buffer.Span);

        if (_closed)
            return 0;

        while (true)
        {
            TlsRecord record;
            try
            {
                record = await _channel.ReadRecordAsync(ct);
            }
            catch (EndOfStreamException)
            {
                _closed = true;
                return 0;
            }

            switch (record.ContentType)
            {
                case TlsConstants.ContentApplicationData:
                    _leftover = _decrypt.Decrypt(TlsConstants.ContentApplicationData, record.Payload);
                    _leftoverOffset = 0;
                    if (_leftover.Length == 0)
                        continue; // empty record, keep reading
                    return CopyLeftover(buffer.Span);

                case TlsConstants.ContentAlert:
                    // close_notify or any alert: treat as end of stream for the POC.
                    _closed = true;
                    return 0;

                default:
                    // Ignore anything unexpected (e.g. renegotiation) rather than crash the demo.
                    continue;
            }
        }
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int chunk = Math.Min(MaxPlaintextPerRecord, buffer.Length - offset);
            byte[] payload = _encrypt.Encrypt(TlsConstants.ContentApplicationData, buffer.Span.Slice(offset, chunk));
            await _channel.WriteRecordAsync(TlsConstants.ContentApplicationData, payload, ct);
            offset += chunk;
        }
    }

    private int CopyLeftover(Span<byte> destination)
    {
        int available = _leftover.Length - _leftoverOffset;
        int take = Math.Min(available, destination.Length);
        _leftover.AsSpan(_leftoverOffset, take).CopyTo(destination);
        _leftoverOffset += take;
        return take;
    }

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Flush() { }
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
