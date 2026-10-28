namespace Sslbump.Tls.Records;

/// <summary>One fully reassembled TLS record: its content type and its raw payload.</summary>
public readonly record struct TlsRecord(byte ContentType, ushort Version, byte[] Payload);

/// <summary>
/// A push-style TLS record framer. You feed it whatever bytes arrive on a socket
/// (in any size chunk) and it calls <see cref="OnRecord"/> once per complete
/// record. Used by the *passive* upstream tap, which must watch bytes flow by
/// without consuming the stream itself.
///
/// Every TLS record starts with a 5-byte header:
///     byte  0    : content type
///     bytes 1..2 : protocol version
///     bytes 3..4 : payload length (big-endian)
/// followed by exactly that many payload bytes.
/// </summary>
public sealed class RecordReassembler
{
    private const int HeaderSize = 5;

    private readonly List<byte> _pending = new(1024);

    /// <summary>Raised once for every complete record reassembled from the fed bytes.</summary>
    public event Action<TlsRecord>? OnRecord;

    public void Feed(ReadOnlySpan<byte> chunk)
    {
        _pending.AddRange(chunk);

        // Emit as many complete records as the buffer currently holds.
        while (_pending.Count >= HeaderSize)
        {
            byte contentType = _pending[0];
            ushort version = (ushort)((_pending[1] << 8) | _pending[2]);
            int length = (_pending[3] << 8) | _pending[4];

            int total = HeaderSize + length;
            if (_pending.Count < total)
                break; // the rest of this record has not arrived yet

            byte[] payload = _pending.GetRange(HeaderSize, length).ToArray();
            _pending.RemoveRange(0, total);

            OnRecord?.Invoke(new TlsRecord(contentType, version, payload));
        }
    }
}
