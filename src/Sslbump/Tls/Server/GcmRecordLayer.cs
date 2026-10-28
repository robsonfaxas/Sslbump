using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Sslbump.Tls.Server;

/// <summary>
/// The AES-128-GCM record protection for TLS 1.2 (RFC 5288), for the browser leg
/// where the proxy is the server. One instance protects records in one direction;
/// the handshake creates two (client-to-server for decrypting, server-to-client
/// for encrypting).
///
/// Nonce   = fixed_iv (4 bytes from the key block) || explicit_nonce (8 bytes on the wire)
/// Record  = explicit_nonce (8) || ciphertext (plaintext length) || auth tag (16)
/// AAD     = seq_num (8) || content_type (1) || version (2) || plaintext_length (2)
/// </summary>
public sealed class GcmRecordLayer
{
    private const int ExplicitNonceLength = 8;
    private const int TagLength = 16;

    private readonly AesGcm _aes;
    private readonly byte[] _fixedIv;
    private ulong _sequenceNumber;

    public GcmRecordLayer(byte[] key, byte[] fixedIv)
    {
        _aes = new AesGcm(key, TagLength);
        _fixedIv = fixedIv;
    }

    /// <summary>Encrypts <paramref name="plaintext"/> and returns the full record payload (nonce|ct|tag).</summary>
    public byte[] Encrypt(byte contentType, ReadOnlySpan<byte> plaintext)
    {
        ulong seq = _sequenceNumber++;

        // Use the sequence number as the explicit per-record nonce. It only has to be
        // unique under one key, and the sequence number is exactly that.
        byte[] explicitNonce = new byte[ExplicitNonceLength];
        BinaryPrimitives.WriteUInt64BigEndian(explicitNonce, seq);

        Span<byte> nonce = stackalloc byte[12];
        _fixedIv.CopyTo(nonce);
        explicitNonce.CopyTo(nonce[SessionKeys.FixedIvLength..]);

        byte[] aad = BuildAad(seq, contentType, plaintext.Length);

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagLength];
        _aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        // Wire payload: explicit nonce, then ciphertext, then tag.
        byte[] record = new byte[ExplicitNonceLength + ciphertext.Length + TagLength];
        explicitNonce.CopyTo(record, 0);
        ciphertext.CopyTo(record, ExplicitNonceLength);
        tag.CopyTo(record, ExplicitNonceLength + ciphertext.Length);
        return record;
    }

    /// <summary>Decrypts a received record payload (nonce|ct|tag) back to plaintext.</summary>
    public byte[] Decrypt(byte contentType, ReadOnlySpan<byte> recordPayload)
    {
        ulong seq = _sequenceNumber++;

        ReadOnlySpan<byte> explicitNonce = recordPayload[..ExplicitNonceLength];
        ReadOnlySpan<byte> ciphertext = recordPayload[ExplicitNonceLength..^TagLength];
        ReadOnlySpan<byte> tag = recordPayload[^TagLength..];

        Span<byte> nonce = stackalloc byte[12];
        _fixedIv.CopyTo(nonce);
        explicitNonce.CopyTo(nonce[SessionKeys.FixedIvLength..]);

        byte[] aad = BuildAad(seq, contentType, ciphertext.Length);

        byte[] plaintext = new byte[ciphertext.Length];
        _aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        return plaintext;
    }

    private static byte[] BuildAad(ulong seq, byte contentType, int plaintextLength)
    {
        byte[] aad = new byte[13];
        BinaryPrimitives.WriteUInt64BigEndian(aad, seq);
        aad[8] = contentType;
        aad[9] = (byte)(TlsConstants.Tls12 >> 8);
        aad[10] = (byte)(TlsConstants.Tls12 & 0xFF);
        aad[11] = (byte)(plaintextLength >> 8);
        aad[12] = (byte)plaintextLength;
        return aad;
    }
}
