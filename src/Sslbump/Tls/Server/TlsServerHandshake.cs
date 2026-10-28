using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sslbump.Certificates;
using Sslbump.Logging;
using Sslbump.Tls.Records;

namespace Sslbump.Tls.Server;

/// <summary>
/// Our hand-rolled TLS 1.2 server for the browser leg. It plays the server side
/// of a single cipher suite (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) and walks
/// through handshake steps 2..10 from the brief, logging each one, so the whole
/// key exchange is visible instead of hidden inside SslStream/SChannel.
///
/// On success it returns a <see cref="TlsServerConnection"/> carrying the agreed
/// keys, over which the decrypted HTTP is relayed.
/// </summary>
public sealed class TlsServerHandshake
{
    private readonly RecordChannel _channel;
    private readonly StepLogger _log;
    private readonly ForgedCertificate _serverCertificate;
    private readonly HandshakeTranscript _transcript = new();

    private const Leg ThisLeg = Leg.BrowserToProxy;

    private byte[] _clientRandom = [];
    private byte[] _serverRandom = [];

    public TlsServerHandshake(RecordChannel channel, StepLogger log, ForgedCertificate serverCertificate)
    {
        _channel = channel;
        _log = log;
        _serverCertificate = serverCertificate;
    }

    public async Task<TlsServerConnection> RunAsync(CancellationToken ct)
    {
        await ReadClientHelloAsync(ct);                    // step 1
        await SendServerHelloAsync(ct);                    // step 2
        await SendCertificateAsync(ct);                    // step 3
        using ECDiffieHellman serverEphemeral = await SendServerKeyExchangeAsync(ct); // step 4
        await SendServerHelloDoneAsync(ct);                // step 5

        byte[] preMasterSecret = await ReadClientKeyExchangeAsync(serverEphemeral, ct); // step 6

        byte[] masterSecret = DeriveSecrets(preMasterSecret, out SessionKeys keys);
        var decrypt = new GcmRecordLayer(keys.ClientWriteKey, keys.ClientWriteIv);
        var encrypt = new GcmRecordLayer(keys.ServerWriteKey, keys.ServerWriteIv);

        await ReadClientChangeCipherSpecAsync(ct);         // step 7
        await ReadClientFinishedAsync(decrypt, masterSecret, ct); // step 8
        await SendServerChangeCipherSpecAsync(ct);         // step 9
        await SendServerFinishedAsync(encrypt, masterSecret, ct); // step 10

        _log.Info(ThisLeg, "Handshake complete - now relaying decrypted HTTP.");
        return new TlsServerConnection(_channel, decrypt, encrypt);
    }

    // ----- step 1: ClientHello ------------------------------------------------

    private async Task ReadClientHelloAsync(CancellationToken ct)
    {
        (byte type, byte[] body) = await ReadHandshakeMessageAsync(ct);
        if (type != TlsConstants.HandshakeClientHello)
            throw new InvalidOperationException($"Expected ClientHello, got handshake type {type}.");

        _transcript.Append(WrapHandshake(type, body));

        // random is right after the 2-byte client_version.
        _clientRandom = body.AsSpan(2, 32).ToArray();

        _log.Step(ThisLeg, 1, "ClientHello  (ciphers, max version and client random)");
        HandshakeDetails.LogClientHello(_log, ThisLeg, body);
    }

    // ----- step 2: ServerHello ------------------------------------------------

    private async Task SendServerHelloAsync(CancellationToken ct)
    {
        _serverRandom = RandomNumberGenerator.GetBytes(32);

        var body = new TlsWriter();
        body.WriteUInt16(TlsConstants.Tls12);          // chosen version: TLS 1.2
        body.WriteBytes(_serverRandom);                // server random
        body.WriteVector8([]);                         // empty session id (no resumption)
        body.WriteUInt16(TlsConstants.CipherEcdheRsaAes128GcmSha256); // chosen cipher
        body.WriteUInt8(0);                            // compression: none

        // Extensions the browser expects back: a (empty) renegotiation_info and ALPN http/1.1.
        var extensions = new TlsWriter();
        WriteRenegotiationInfo(extensions);
        WriteAlpnHttp11(extensions);
        body.WriteVector16(extensions.ToArray());

        await SendHandshakeAsync(TlsConstants.HandshakeServerHello, body.ToArray(), ct);

        _log.Step(ThisLeg, 2, "ServerHello  (chose cipher, version and server random)");
        _log.Detail(ThisLeg, "chosen version", "TLS 1.2");
        _log.Detail(ThisLeg, "chosen cipher", "0xC02F TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
        _log.Detail(ThisLeg, "server random", _serverRandom);
    }

    private static void WriteRenegotiationInfo(TlsWriter extensions)
    {
        extensions.WriteUInt16(0xFF01);                // extension type: renegotiation_info
        extensions.WriteUInt16(1);                     // extension length
        extensions.WriteUInt8(0);                      // empty "renegotiated_connection"
    }

    private static void WriteAlpnHttp11(TlsWriter extensions)
    {
        var protocol = "http/1.1"u8;
        var list = new TlsWriter();
        list.WriteVector8(protocol);                   // one protocol name

        var alpn = new TlsWriter();
        alpn.WriteVector16(list.ToArray());            // ProtocolNameList

        extensions.WriteUInt16(0x0010);                // extension type: application_layer_protocol_negotiation
        extensions.WriteVector16(alpn.ToArray());
    }

    // ----- step 3: Certificate ------------------------------------------------

    private async Task SendCertificateAsync(CancellationToken ct)
    {
        byte[] leafDer = _serverCertificate.Certificate.RawData;

        var list = new TlsWriter();
        list.WriteVector24(leafDer);                   // leaf first

        var body = new TlsWriter();
        body.WriteVector24(list.ToArray());            // certificate_list

        await SendHandshakeAsync(TlsConstants.HandshakeCertificate, body.ToArray(), ct);

        _log.Step(ThisLeg, 3, "Certificate  (forged leaf; browser checks it against our CA)");
        _log.Detail(ThisLeg, "leaf subject", _serverCertificate.Certificate.Subject);
        _log.Detail(ThisLeg, "SHA-256 of leaf cert", SHA256.HashData(leafDer));
    }

    // ----- step 4: ServerKeyExchange -----------------------------------------

    private async Task<ECDiffieHellman> SendServerKeyExchangeAsync(CancellationToken ct)
    {
        // Our ephemeral ECDHE key pair on curve P-256. "Ephemeral" = created fresh
        // per connection and thrown away afterwards (this is the 'E' in ECDHE).
        var serverEphemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        ECParameters pub = serverEphemeral.PublicKey.ExportParameters();

        byte[] point = EncodeUncompressedPoint(pub.Q.X!, pub.Q.Y!);

        // ServerECDHParams: curve_type=named_curve(3), named_curve=secp256r1(23), public point.
        var ecdhParams = new TlsWriter();
        ecdhParams.WriteUInt8(3);
        ecdhParams.WriteUInt16(TlsConstants.NamedGroupSecp256r1);
        ecdhParams.WriteVector8(point);
        byte[] paramsBytes = ecdhParams.ToArray();

        // Signature proves these ephemeral params really come from the certificate
        // holder: sign client_random || server_random || params with the leaf's RSA key.
        byte[] toSign = [.. _clientRandom, .. _serverRandom, .. paramsBytes];
        byte[] signature = _serverCertificate.PrivateKey.SignData(
            toSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var body = new TlsWriter();
        body.WriteBytes(paramsBytes);
        body.WriteUInt16(TlsConstants.SignatureRsaPkcs1Sha256); // {sha256, rsa}
        body.WriteVector16(signature);

        await SendHandshakeAsync(TlsConstants.HandshakeServerKeyExchange, body.ToArray(), ct);

        _log.Step(ThisLeg, 4, "ServerKeyExchange  (fresh ephemeral ECDHE key, signed with the leaf)");
        _log.Detail(ThisLeg, "curve", "secp256r1 (P-256)");
        _log.Detail(ThisLeg, "server ephemeral public point", point);
        return serverEphemeral;
    }

    // ----- step 5: ServerHelloDone -------------------------------------------

    private async Task SendServerHelloDoneAsync(CancellationToken ct)
    {
        await SendHandshakeAsync(TlsConstants.HandshakeServerHelloDone, [], ct);
        _log.Step(ThisLeg, 5, "ServerHelloDone  (server is done talking, over to the client)");
    }

    // ----- step 6: ClientKeyExchange + shared secret -------------------------

    private async Task<byte[]> ReadClientKeyExchangeAsync(ECDiffieHellman serverEphemeral, CancellationToken ct)
    {
        (byte type, byte[] body) = await ReadHandshakeMessageAsync(ct);
        if (type != TlsConstants.HandshakeClientKeyExchange)
            throw new InvalidOperationException($"Expected ClientKeyExchange, got handshake type {type}.");

        _transcript.Append(WrapHandshake(type, body));

        // The body is the client's ephemeral public point (1-byte length prefix).
        var r = new TlsReader(body);
        ReadOnlySpan<byte> clientPoint = r.ReadVector8();

        using ECDiffieHellman clientPublic = ImportPublicPoint(clientPoint);

        // Both sides multiply their own private key by the other's public key and
        // arrive at the same point; its X coordinate is the pre-master secret.
        byte[] preMasterSecret = serverEphemeral.DeriveRawSecretAgreement(clientPublic.PublicKey);

        _log.Step(ThisLeg, 6, "ClientKeyExchange  (client's ephemeral public key -> shared secret)");
        _log.Detail(ThisLeg, "client ephemeral public point", clientPoint);
        _log.Detail(ThisLeg, "pre-master secret (ECDHE shared X)", preMasterSecret);
        return preMasterSecret;
    }

    private byte[] DeriveSecrets(byte[] preMasterSecret, out SessionKeys keys)
    {
        // Feed the shared secret + both randoms through the PRF for the master secret,
        // then expand that into the actual AES keys and IVs.
        byte[] masterSecret = Prf.DeriveMasterSecret(preMasterSecret, _clientRandom, _serverRandom);
        byte[] keyBlock = Prf.DeriveKeyBlock(masterSecret, _serverRandom, _clientRandom, SessionKeys.KeyBlockLength);
        keys = SessionKeys.FromKeyBlock(keyBlock);

        _log.Detail(ThisLeg, "master secret", masterSecret);
        _log.Detail(ThisLeg, "client write key", keys.ClientWriteKey);
        _log.Detail(ThisLeg, "server write key", keys.ServerWriteKey);
        return masterSecret;
    }

    // ----- step 7: client ChangeCipherSpec -----------------------------------

    private async Task ReadClientChangeCipherSpecAsync(CancellationToken ct)
    {
        TlsRecord record = await _channel.ReadRecordAsync(ct);
        if (record.ContentType != TlsConstants.ContentChangeCipherSpec)
            throw new InvalidOperationException("Expected the client's ChangeCipherSpec.");

        _log.Step(ThisLeg, 7, "ChangeCipherSpec (client) - client will now encrypt everything");
    }

    // ----- step 8: client Finished (first encrypted message) -----------------

    private async Task ReadClientFinishedAsync(GcmRecordLayer decrypt, byte[] masterSecret, CancellationToken ct)
    {
        TlsRecord record = await _channel.ReadRecordAsync(ct);
        if (record.ContentType != TlsConstants.ContentHandshake)
            throw new InvalidOperationException("Expected the client's encrypted Finished.");

        // Decrypt the very first protected record and confirm it is a Finished.
        byte[] plaintext = decrypt.Decrypt(TlsConstants.ContentHandshake, record.Payload);

        byte type = plaintext[0];
        int length = (plaintext[1] << 16) | (plaintext[2] << 8) | plaintext[3];
        ReadOnlySpan<byte> verifyData = plaintext.AsSpan(4, length);

        // Recompute what the client's verify_data should be and compare.
        byte[] expected = Prf.Compute(masterSecret, "client finished", _transcript.CurrentHash(), 12);
        bool ok = CryptographicOperations.FixedTimeEquals(verifyData, expected);

        if (type != TlsConstants.HandshakeFinished || !ok)
            throw new InvalidOperationException("Client Finished did not verify - handshake integrity check failed.");

        // Only now add the client Finished to the transcript, for the server Finished below.
        _transcript.Append(plaintext);

        _log.Step(ThisLeg, 8, "Finished (client) - decrypted and verify_data matched");
        _log.Detail(ThisLeg, "client verify_data", verifyData);
    }

    // ----- step 9: server ChangeCipherSpec ------------------------------------

    private async Task SendServerChangeCipherSpecAsync(CancellationToken ct)
    {
        await _channel.WriteRecordAsync(TlsConstants.ContentChangeCipherSpec, [0x01], ct);
        _log.Step(ThisLeg, 9, "ChangeCipherSpec (server) - server turns on its own encryption");
    }

    // ----- step 10: server Finished -------------------------------------------

    private async Task SendServerFinishedAsync(GcmRecordLayer encrypt, byte[] masterSecret, CancellationToken ct)
    {
        byte[] verifyData = Prf.Compute(masterSecret, "server finished", _transcript.CurrentHash(), 12);

        var finished = new TlsWriter();
        finished.WriteUInt8(TlsConstants.HandshakeFinished);
        finished.WriteVector24(verifyData);
        byte[] plaintext = finished.ToArray();

        byte[] protectedPayload = encrypt.Encrypt(TlsConstants.ContentHandshake, plaintext);
        await _channel.WriteRecordAsync(TlsConstants.ContentHandshake, protectedPayload, ct);

        _log.Step(ThisLeg, 10, "Finished (server) - encrypted summary sent; handshake done!");
        _log.Detail(ThisLeg, "server verify_data", verifyData);
    }

    // ----- helpers ------------------------------------------------------------

    private async Task<(byte Type, byte[] Body)> ReadHandshakeMessageAsync(CancellationToken ct)
    {
        TlsRecord record = await _channel.ReadRecordAsync(ct);
        if (record.ContentType != TlsConstants.ContentHandshake)
            throw new InvalidOperationException($"Expected a handshake record, got content type {record.ContentType}.");

        byte type = record.Payload[0];
        int length = (record.Payload[1] << 16) | (record.Payload[2] << 8) | record.Payload[3];
        byte[] body = record.Payload.AsSpan(4, length).ToArray();
        return (type, body);
    }

    private async Task SendHandshakeAsync(byte type, byte[] body, CancellationToken ct)
    {
        byte[] message = WrapHandshake(type, body);
        _transcript.Append(message);
        await _channel.WriteRecordAsync(TlsConstants.ContentHandshake, message, ct);
    }

    /// <summary>Prefixes a handshake body with its 1-byte type and 3-byte length.</summary>
    private static byte[] WrapHandshake(byte type, byte[] body)
    {
        var w = new TlsWriter();
        w.WriteUInt8(type);
        w.WriteVector24(body);
        return w.ToArray();
    }

    private static byte[] EncodeUncompressedPoint(byte[] x, byte[] y)
    {
        // Uncompressed EC point: 0x04 || X || Y, each coordinate 32 bytes for P-256.
        byte[] point = new byte[1 + 32 + 32];
        point[0] = 0x04;
        x.CopyTo(point, 1 + (32 - x.Length));
        y.CopyTo(point, 1 + 32 + (32 - y.Length));
        return point;
    }

    private static ECDiffieHellman ImportPublicPoint(ReadOnlySpan<byte> point)
    {
        // Expect an uncompressed point: 0x04 || X(32) || Y(32).
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = point.Slice(1, 32).ToArray(),
                Y = point.Slice(33, 32).ToArray(),
            },
        };

        var ecdh = ECDiffieHellman.Create();
        ecdh.ImportParameters(parameters);
        return ecdh;
    }
}
