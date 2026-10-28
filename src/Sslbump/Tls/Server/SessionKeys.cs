namespace Sslbump.Tls.Server;

/// <summary>
/// The symmetric keys carved out of the key block for
/// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.
///
/// This suite is an AEAD suite, so there are no separate MAC keys. The key block
/// is laid out as:
///     client_write_key (16) | server_write_key (16) | client_write_IV (4) | server_write_IV (4)
/// The 4-byte IVs are the "salt" (fixed part) of the AES-GCM nonce.
/// </summary>
public sealed class SessionKeys
{
    public const int KeyLength = 16;
    public const int FixedIvLength = 4;
    public const int KeyBlockLength = (KeyLength * 2) + (FixedIvLength * 2); // 40 bytes

    public byte[] ClientWriteKey { get; }
    public byte[] ServerWriteKey { get; }
    public byte[] ClientWriteIv { get; }
    public byte[] ServerWriteIv { get; }

    private SessionKeys(byte[] clientKey, byte[] serverKey, byte[] clientIv, byte[] serverIv)
    {
        ClientWriteKey = clientKey;
        ServerWriteKey = serverKey;
        ClientWriteIv = clientIv;
        ServerWriteIv = serverIv;
    }

    public static SessionKeys FromKeyBlock(ReadOnlySpan<byte> keyBlock)
    {
        int offset = 0;

        byte[] clientKey = keyBlock.Slice(offset, KeyLength).ToArray(); offset += KeyLength;
        byte[] serverKey = keyBlock.Slice(offset, KeyLength).ToArray(); offset += KeyLength;
        byte[] clientIv = keyBlock.Slice(offset, FixedIvLength).ToArray(); offset += FixedIvLength;
        byte[] serverIv = keyBlock.Slice(offset, FixedIvLength).ToArray();

        return new SessionKeys(clientKey, serverKey, clientIv, serverIv);
    }
}
