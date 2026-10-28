namespace Sslbump.Tls;

/// <summary>
/// The handful of TLS 1.2 constants this POC cares about. We deliberately
/// support exactly one cipher suite so the hybrid server stays small and the
/// steps stay easy to follow.
/// </summary>
public static class TlsConstants
{
    // Record-layer content types (the first byte of every TLS record).
    public const byte ContentChangeCipherSpec = 20;
    public const byte ContentAlert            = 21;
    public const byte ContentHandshake        = 22;
    public const byte ContentApplicationData  = 23;

    // Handshake message types (the first byte inside a handshake record).
    public const byte HandshakeClientHello        = 1;
    public const byte HandshakeServerHello        = 2;
    public const byte HandshakeNewSessionTicket   = 4;
    public const byte HandshakeCertificate        = 11;
    public const byte HandshakeServerKeyExchange  = 12;
    public const byte HandshakeServerHelloDone    = 14;
    public const byte HandshakeClientKeyExchange  = 16;
    public const byte HandshakeFinished           = 20;

    // Protocol version on the wire. 0x0303 == TLS 1.2.
    public const ushort Tls12 = 0x0303;

    /// <summary>TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 — the one suite we negotiate.</summary>
    public const ushort CipherEcdheRsaAes128GcmSha256 = 0xC02F;

    /// <summary>Named curve secp256r1 (a.k.a. NIST P-256), group id 23.</summary>
    public const ushort NamedGroupSecp256r1 = 23;

    /// <summary>SignatureAndHashAlgorithm { sha256(4), rsa(1) } used to sign the ServerKeyExchange.</summary>
    public const ushort SignatureRsaPkcs1Sha256 = 0x0401;

    /// <summary>Human-readable name for a handshake message type, for logging.</summary>
    public static string HandshakeName(byte type) => type switch
    {
        HandshakeClientHello       => "ClientHello",
        HandshakeServerHello       => "ServerHello",
        HandshakeNewSessionTicket  => "NewSessionTicket (session resumption hint, sent in the clear)",
        HandshakeCertificate       => "Certificate",
        HandshakeServerKeyExchange => "ServerKeyExchange",
        HandshakeServerHelloDone   => "ServerHelloDone",
        HandshakeClientKeyExchange => "ClientKeyExchange",
        HandshakeFinished          => "Finished",
        _                          => $"Handshake(type {type})",
    };
}
