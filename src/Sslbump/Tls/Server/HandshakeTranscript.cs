using System.Security.Cryptography;

namespace Sslbump.Tls.Server;

/// <summary>
/// Keeps a running copy of every handshake message (type + length + body, as it
/// appears on the wire, but without the record header) so the Finished messages
/// can be verified and generated.
///
/// The Finished "verify_data" is PRF over the SHA-256 hash of all handshake
/// messages seen so far, so the exact bytes and their order matter.
/// </summary>
public sealed class HandshakeTranscript
{
    private readonly List<byte> _messages = new(4096);

    /// <summary>Appends one complete handshake message (including its 4-byte header).</summary>
    public void Append(ReadOnlySpan<byte> handshakeMessage) => _messages.AddRange(handshakeMessage);

    /// <summary>SHA-256 over everything appended so far. Called at each Finished.</summary>
    public byte[] CurrentHash() => SHA256.HashData(_messages.ToArray());
}
