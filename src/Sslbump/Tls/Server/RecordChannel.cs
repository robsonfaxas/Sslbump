using Sslbump.Tls.Records;

namespace Sslbump.Tls.Server;

/// <summary>
/// Reads and writes raw TLS records over the browser socket on the leg where the
/// proxy owns the whole conversation (so, unlike the upstream tap, this one
/// actually consumes the stream). It knows nothing about encryption: before the
/// ChangeCipherSpec the payloads are plaintext handshake bytes, after it the
/// caller hands over already-encrypted payloads. Either way a record is just a
/// 5-byte header plus its payload.
/// </summary>
public sealed class RecordChannel
{
    private readonly Stream _stream;

    public RecordChannel(Stream stream) => _stream = stream;

    public async Task<TlsRecord> ReadRecordAsync(CancellationToken ct)
    {
        byte[] header = await ReadExactlyAsync(5, ct);

        byte contentType = header[0];
        ushort version = (ushort)((header[1] << 8) | header[2]);
        int length = (header[3] << 8) | header[4];

        byte[] payload = await ReadExactlyAsync(length, ct);
        return new TlsRecord(contentType, version, payload);
    }

    public async Task WriteRecordAsync(byte contentType, byte[] payload, CancellationToken ct)
    {
        byte[] record = new byte[5 + payload.Length];
        record[0] = contentType;
        record[1] = (byte)(TlsConstants.Tls12 >> 8);
        record[2] = (byte)(TlsConstants.Tls12 & 0xFF);
        record[3] = (byte)(payload.Length >> 8);
        record[4] = (byte)payload.Length;
        payload.CopyTo(record, 5);

        await _stream.WriteAsync(record, ct);
        await _stream.FlushAsync(ct);
    }

    private async Task<byte[]> ReadExactlyAsync(int count, CancellationToken ct)
    {
        byte[] buffer = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int read = await _stream.ReadAsync(buffer.AsMemory(offset, count - offset), ct);
            if (read == 0)
                throw new EndOfStreamException("The peer closed the connection mid-record.");
            offset += read;
        }
        return buffer;
    }
}
