namespace Sslbump.Tls.Records;

/// <summary>
/// A tiny append-only buffer for building TLS messages by hand.
///
/// TLS encodes lengths big-endian and uses a lot of "length-prefixed" blobs
/// (1-, 2- or 3-byte length followed by that many bytes). The helpers here let
/// the handshake code read almost like the wire format itself.
/// </summary>
public sealed class TlsWriter
{
    private readonly List<byte> _buffer = new(256);

    public int Length => _buffer.Count;

    public void WriteUInt8(int value) => _buffer.Add((byte)value);

    public void WriteUInt16(int value)
    {
        _buffer.Add((byte)(value >> 8));
        _buffer.Add((byte)value);
    }

    public void WriteUInt24(int value)
    {
        _buffer.Add((byte)(value >> 16));
        _buffer.Add((byte)(value >> 8));
        _buffer.Add((byte)value);
    }

    public void WriteBytes(ReadOnlySpan<byte> bytes) => _buffer.AddRange(bytes);

    /// <summary>Writes a 1-byte length followed by the block.</summary>
    public void WriteVector8(ReadOnlySpan<byte> block)
    {
        WriteUInt8(block.Length);
        WriteBytes(block);
    }

    /// <summary>Writes a 2-byte length followed by the block.</summary>
    public void WriteVector16(ReadOnlySpan<byte> block)
    {
        WriteUInt16(block.Length);
        WriteBytes(block);
    }

    /// <summary>Writes a 3-byte length followed by the block.</summary>
    public void WriteVector24(ReadOnlySpan<byte> block)
    {
        WriteUInt24(block.Length);
        WriteBytes(block);
    }

    public byte[] ToArray() => _buffer.ToArray();
}
