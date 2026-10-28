# Sslbump

A didactic TLS-intercepting (man-in-the-middle) HTTP proxy, built on **.NET 10**
using **only the base class library** — no YARP, no Titanium, no third-party
packages. It exists to make the TLS 1.2 handshake *visible*.

```
browser  ->  Sslbump  ->  destination server
```

Sslbump terminates TLS on both sides. On the **browser leg** it is a
hand-rolled TLS 1.2 server, so every handshake step — including the ECDHE key
exchange, the pre-master secret, the master secret, the derived keys and both
`verify_data` values — is computed by this code and printed. On the **origin
leg** it is a normal `SslStream` client with a passive record *tap*, so the real
handshake is logged step by step up to the point where it turns encrypted.

## The TLS 1.2 steps you see

| Step | Message | Browser leg (hand-rolled) | Origin leg (SslStream + tap) |
|------|---------|---------------------------|------------------------------|
| 0 | TCP established | logged on accept | logged on connect |
| 1 | ClientHello | parsed (random, ciphers, SNI) | parsed |
| 2 | ServerHello | we choose cipher/version | parsed |
| 3 | Certificate | forged leaf + SHA-256 | real chain + SHA-256 |
| 4 | ServerKeyExchange | our ephemeral ECDHE key, signed | parsed |
| 5 | ServerHelloDone | sent | parsed |
| 6 | ClientKeyExchange | **shared secret + PRF shown** | parsed (point only) |
| 7 | ChangeCipherSpec (client) | observed | observed |
| 8 | Finished (client) | **decrypted and verified** | encrypted (size only) |
| 9 | ChangeCipherSpec (server) | sent | observed |
| 10 | Finished (server) | **generated and sent** | encrypted (size only) |

Step 0 is handled by the OS TCP stack (the actual SYN/SYN-ACK/ACK packets are
not visible to a socket — use Wireshark for those); we log the moment the
connection is established. Step 3's signature *validation* is done by the
browser, not the proxy; on the browser leg we print the leaf's SHA-256 so you
can see the hash the browser recomputes.

## Cipher suite

Exactly one, on purpose, to keep the code small and readable:
**`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`** (0xC02F) on curve **P-256**.
Both legs are pinned to TLS 1.2 (TLS 1.3 drops ServerKeyExchange and
ServerHelloDone). A few origins are 1.3-only and will fail with a logged error.

## Running it

```bash
dotnet run --project src/Sslbump -- --port 8080
```

On first run it creates `ca.pfx` (private, used by the proxy) and `ca.cer`
(public). To make a browser trust the forged certificates, install the CA into
the Windows trust store **yourself** (the proxy never touches the trust store):

```
certutil -addstore -f Root "ca.cer"      # run as administrator
```

Remove it when you are done:

```
certutil -delstore Root "Sslbump POC Root CA"
```

Then point the browser (or the OS proxy settings) at `localhost:8080` for both
HTTP and HTTPS. Quick check without installing anything, using curl's own
trust-skip (`-k`) to isolate the handshake:

```bash
curl -x http://localhost:8080 -k --tlsv1.2 https://example.com/
```

## Tampering with traffic (man-in-the-middle demo)

Because the proxy terminates both TLS sessions, the HTTP in the middle is
plaintext and can be *modified*, not just read. The `--inject` flag splices a
banner of your text into every HTML response before re-encrypting it to the
browser:

```bash
dotnet run --project src/Sslbump -- --port 8080 --inject "Robson changed it"
```

Browse to an HTTP(S) page and your text appears at the top of the page body,
served under the site's own (forged-but-trusted) certificate. The console logs
`** INJECTED ... **` with the before/after byte counts. To keep the edit valid,
the proxy strips `Accept-Encoding` (so the origin replies uncompressed), rewrites
the body, and fixes `Content-Length`. Non-HTML responses (images, scripts,
already-compressed bodies) stream through untouched. Omit the flag and all
traffic is relayed verbatim.

The same join point could edit the **request** (browser -> origin) instead; the
injector here targets the response because that is what the browser renders.

## Project layout

```
src/Sslbump/
  Program.cs                      entry point and CLI
  Proxy/
    ProxyServer.cs                TcpListener, routes CONNECT vs plain HTTP
    HttpHead.cs                   minimal HTTP head read/parse/rewrite
    HttpForwarder.cs              plain HTTP (port 80) proxying
    ConnectTunnel.cs              CONNECT -> man-in-the-middle, relays decrypted HTTP
  Certificates/
    CertificateAuthority.cs       creates/loads the root CA
    LeafCertificateFactory.cs     forges + caches a per-host leaf, signed by the CA
  Tls/
    TlsConstants.cs               the constants for our one cipher suite
    TappedStream.cs               passive record tap for the origin leg
    Records/
      TlsWriter.cs / TlsReader.cs big-endian + length-prefixed helpers
      RecordReassembler.cs        push-style record framer (for the tap)
      HandshakeTapInterpreter.cs  logs steps from tapped records
      HandshakeDetails.cs         pulls fields out of ClientHello/ServerHello/Certificate
    Server/                       the hand-rolled TLS 1.2 server (browser leg)
      TlsServerHandshake.cs       orchestrates steps 2..10
      Prf.cs                      TLS 1.2 PRF, master secret, key block
      SessionKeys.cs              key-block layout for the suite
      GcmRecordLayer.cs           AES-128-GCM record encrypt/decrypt
      RecordChannel.cs            raw record read/write over the browser socket
      HandshakeTranscript.cs      running hash for the Finished messages
      TlsServerConnection.cs      established connection, exposed as a Stream
  Logging/
    StepLogger.cs                 numbered, colour-coded, per-connection output
```

## Scope / caveats

This is a proof of concept for learning, to run against your own machine with
your own CA. It accepts any origin certificate, supports one cipher suite,
forces `Connection: close`, handles HTTP/1.1 only (no HTTP/2), and is not
hardened for production use.
