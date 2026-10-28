namespace Sslbump.Tls.Records;

/// <summary>
/// A forward-only reader over a byte buffer that already holds a complete TLS
/// structure. It mirrors <see cref="TlsWriter"/>: big-endian integers and the
/// 1/2/3-byte length-prefixed vectors TLS uses everywhere.
/// </summary>
public ref struct TlsReader(ReadOnlySpan<byte> data)
{
    private ReadOnlySpan<byte> _data = data;
    private int _pos = 0;

    public readonly int Remaining => _data.Length - _pos;
    public readonly bool IsEmpty => Remaining == 0;

    public byte ReadUInt8() => _data[_pos++];

    public ushort ReadUInt16()
    {
        ushort value = (ushort)((_data[_pos] << 8) | _data[_pos + 1]);
        _pos += 2;
        return value;
    }

    public int ReadUInt24()
    {
        int value = (_data[_pos] << 16) | (_data[_pos + 1] << 8) | _data[_pos + 2];
        _pos += 3;
        return value;
    }

    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        ReadOnlySpan<byte> slice = _data.Slice(_pos, count);
        _pos += count;
        return slice;
    }

    /// <summary>Reads a block introduced by a 1-byte length.</summary>
    public ReadOnlySpan<byte> ReadVector8() => ReadBytes(ReadUInt8());

    /// <summary>Reads a block introduced by a 2-byte length.</summary>
    public ReadOnlySpan<byte> ReadVector16() => ReadBytes(ReadUInt16());

    /// <summary>Skips <paramref name="count"/> bytes without returning them.</summary>
    public void Skip(int count) => _pos += count;
}
