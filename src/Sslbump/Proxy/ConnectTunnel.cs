using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using Sslbump.Certificates;
using Sslbump.Logging;
using Sslbump.Tls.Server;

namespace Sslbump.Proxy;

/// <summary>
/// Handles the HTTPS case. The browser sends <c>CONNECT host:443 HTTP/1.1</c>
/// expecting a transparent tunnel; instead the proxy answers 200, then becomes
/// the man-in-the-middle:
///
///     browser  ==(our hand-rolled TLS 1.2 server)==>  proxy
///     proxy    ==(SslStream client, with a record tap)==>  origin
///
/// Both TLS sessions are terminated here, so the HTTP flowing between them is in
/// the clear and can be logged. Each leg logs handshake steps 0..10.
/// </summary>
public sealed class ConnectTunnel
{
    private readonly StepLogger _log;
    private readonly LeafCertificateFactory _leafFactory;
    private readonly ContentInjection _injection;

    public ConnectTunnel(StepLogger log, LeafCertificateFactory leafFactory, ContentInjection injection)
    {
        _log = log;
        _leafFactory = leafFactory;
        _injection = injection;
    }

    public async Task HandleAsync(HttpHead connectHead, Stream browser, CancellationToken ct)
    {
        // "CONNECT host:443 HTTP/1.1"
        string[] parts = connectHead.StartLine.Split(' ');
        string[] target = parts[1].Split(':');
        string host = target[0];
        int port = target.Length > 1 ? int.Parse(target[1]) : 443;

        _log.Info(Leg.BrowserToProxy, $"CONNECT {host}:{port} - setting up man-in-the-middle");

        // Tell the browser the tunnel is open; it will immediately start its TLS handshake.
        await browser.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray(), ct);

        // Browser leg: our own TLS 1.2 server, using a certificate forged for this host.
        ForgedCertificate certificate = _leafFactory.GetFor(host);
        var channel = new RecordChannel(browser);
        var handshake = new TlsServerHandshake(channel, _log, certificate);
        await using TlsServerConnection browserTls = await handshake.RunAsync(ct);

        // Origin leg: a normal SslStream client, but over a tapped stream so we can
        // log the real handshake steps as they go by.
        await using Stream originTls = await ConnectUpstreamAsync(host, port, ct);

        // Both ends are now plaintext HTTP to us: relay and log it.
        await RelayHttpAsync(browserTls, originTls, ct);
    }

    private async Task<Stream> ConnectUpstreamAsync(string host, int port, CancellationToken ct)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(host, port, ct);
        _log.Step(Leg.ProxyToOrigin, 0, $"TCP established to {host}:{port}");

        // The tap sits under SslStream and logs steps 1..10 of this leg.
        var tapped = new Sslbump.Tls.TappedStream(tcp.GetStream(), _log, Leg.ProxyToOrigin);

        var ssl = new SslStream(tapped, leaveInnerStreamOpen: false, ValidateOriginCertificate);

        var options = new SslClientAuthenticationOptions
        {
            TargetHost = host,
            // Force TLS 1.2 so the brief's ServerKeyExchange / ServerHelloDone steps exist
            // (TLS 1.3 removes them). Some origins are 1.3-only and will fail here; that is fine.
            EnabledSslProtocols = SslProtocols.Tls12,
            ApplicationProtocols = [SslApplicationProtocol.Http11],
        };

        await ssl.AuthenticateAsClientAsync(options, ct);
        return ssl;
    }

    private bool ValidateOriginCertificate(
        object sender,
        System.Security.Cryptography.X509Certificates.X509Certificate? certificate,
        System.Security.Cryptography.X509Certificates.X509Chain? chain,
        SslPolicyErrors errors)
    {
        if (certificate is not null)
            _log.Detail(Leg.ProxyToOrigin, "origin certificate subject", certificate.Subject);
        if (errors != SslPolicyErrors.None)
            _log.Info(Leg.ProxyToOrigin, $"origin certificate issues: {errors} (accepted anyway for the POC)");

        // A POC MITM accepts whatever the origin presents. A real tool would validate here.
        return true;
    }

    private async Task RelayHttpAsync(Stream browser, Stream origin, CancellationToken ct)
    {
        HttpHead? request = await HttpHead.ReadAsync(browser, ct);
        if (request is null)
            return;

        _log.Http($"{request.StartLine}  (decrypted from the browser)");

        // HTTPS request lines are already origin-form; just force Connection: close.
        // When tampering is on we also drop Accept-Encoding so the body arrives uncompressed.
        byte[] head = request.ToForwardedBytes(request.StartLine, stripAcceptEncoding: _injection.Enabled);
        await origin.WriteAsync(head, ct);

        Task requestBody = HttpForwarder.CopyAsync(browser, origin, ct);

        HttpHead? response = await HttpHead.ReadAsync(origin, ct);
        if (response is not null)
        {
            _log.Http($"response: {response.StartLine}");
            await HttpForwarder.ForwardResponseAsync(response, origin, browser, _injection, _log, ct);
        }

        try { await requestBody; } catch { /* request side usually ends first */ }
    }
}
