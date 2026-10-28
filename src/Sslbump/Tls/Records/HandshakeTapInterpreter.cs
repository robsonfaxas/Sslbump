using Sslbump.Logging;

namespace Sslbump.Tls.Records;

/// <summary>
/// Interprets the records of one direction of a TLS conversation and logs the
/// numbered handshake steps. This is the *read-only* view used on the upstream
/// (proxy -> origin) leg, which runs on a real <c>SslStream</c>: we can parse
/// every handshake message in the clear up to ChangeCipherSpec, after which the
/// records are encrypted and we can only report their size.
/// </summary>
public sealed class HandshakeTapInterpreter
{
    private readonly StepLogger _log;
    private readonly Leg _leg;
    private readonly bool _fromClient;

    private readonly List<byte> _handshakeBuffer = new(4096);
    private bool _encrypted;
    private bool _finishedLogged;

    /// <param name="fromClient">
    /// True for the direction the TLS *client* sends (here: proxy -> origin),
    /// which disambiguates the two ChangeCipherSpec / Finished steps.
    /// </param>
    public HandshakeTapInterpreter(StepLogger log, Leg leg, bool fromClient)
    {
        _log = log;
        _leg = leg;
        _fromClient = fromClient;
    }

    public void Consume(TlsRecord record)
    {
        switch (record.ContentType)
        {
            case TlsConstants.ContentHandshake:
                if (_encrypted)
                    LogEncryptedFinished(record);
                else
                    ReassembleAndLog(record.Payload);
                break;

            case TlsConstants.ContentChangeCipherSpec:
                // Steps 7 (client) and 9 (server): "everything after this is encrypted".
                _log.Step(_leg, _fromClient ? 7 : 9,
                    $"ChangeCipherSpec ({(_fromClient ? "client" : "server")}) - switching to encrypted records");
                _encrypted = true;
                break;

            case TlsConstants.ContentApplicationData:
                // On the upstream leg the decrypted HTTP is logged elsewhere; here we
                // only note that encrypted application data is flowing.
                break;

            case TlsConstants.ContentAlert:
                _log.Info(_leg, $"TLS alert record ({record.Payload.Length} bytes)");
                break;
        }
    }

    private void ReassembleAndLog(byte[] payload)
    {
        _handshakeBuffer.AddRange(payload);

        // A record may carry several handshake messages, and one message may span
        // records, so parse out every *complete* message currently buffered.
        while (_handshakeBuffer.Count >= 4)
        {
            byte type = _handshakeBuffer[0];
            int length = (_handshakeBuffer[1] << 16) | (_handshakeBuffer[2] << 8) | _handshakeBuffer[3];
            int total = 4 + length;

            if (_handshakeBuffer.Count < total)
                break;

            byte[] body = _handshakeBuffer.GetRange(4, length).ToArray();
            _handshakeBuffer.RemoveRange(0, total);

            LogHandshakeMessage(type, body);
        }
    }

    private void LogHandshakeMessage(byte type, byte[] body)
    {
        switch (type)
        {
            case TlsConstants.HandshakeClientHello:
                _log.Step(_leg, 1, "ClientHello  (ciphers, max version and client random)");
                HandshakeDetails.LogClientHello(_log, _leg, body);
                break;

            case TlsConstants.HandshakeServerHello:
                _log.Step(_leg, 2, "ServerHello  (chosen cipher, version and server random)");
                HandshakeDetails.LogServerHello(_log, _leg, body);
                break;

            case TlsConstants.HandshakeCertificate:
                _log.Step(_leg, 3, "Certificate  (server's certificate chain + signature)");
                HandshakeDetails.LogCertificate(_log, _leg, body);
                break;

            case TlsConstants.HandshakeServerKeyExchange:
                _log.Step(_leg, 4, "ServerKeyExchange  (server's ephemeral ECDHE public key, signed)");
                break;

            case TlsConstants.HandshakeServerHelloDone:
                _log.Step(_leg, 5, "ServerHelloDone  (server finished its part of the hello)");
                break;

            case TlsConstants.HandshakeClientKeyExchange:
                _log.Step(_leg, 6, "ClientKeyExchange  (client's ephemeral ECDHE public key)");
                break;

            default:
                _log.Info(_leg, TlsConstants.HandshakeName(type));
                break;
        }
    }

    private void LogEncryptedFinished(TlsRecord record)
    {
        if (_finishedLogged)
            return;
        _finishedLogged = true;

        // The Finished message is the first thing sent after ChangeCipherSpec, so it
        // is already encrypted. On this leg we can only see its length.
        _log.Step(_leg, _fromClient ? 8 : 10,
            $"Finished ({(_fromClient ? "client" : "server")}) - encrypted handshake summary, {record.Payload.Length} bytes");
    }
}
