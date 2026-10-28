using System.Net.Sockets;
using Sslbump.Logging;

namespace Sslbump.Proxy;

/// <summary>
/// Handles ordinary (non-encrypted) HTTP proxying: the browser sends
/// <c>GET http://host/path HTTP/1.1</c> in absolute form, we open a plain TCP
/// connection to the origin on port 80, rewrite the request to origin form and
/// relay both directions, logging the request and response lines.
/// </summary>
public sealed class HttpForwarder
{
    private readonly StepLogger _log;
    private readonly ContentInjection _injection;

    public HttpForwarder(StepLogger log, ContentInjection injection)
    {
        _log = log;
        _injection = injection;
    }

    public async Task HandleAsync(HttpHead requestHead, Stream browser, CancellationToken ct)
    {
        // Absolute-form request line, e.g. "GET http://example.com/path HTTP/1.1".
        string[] parts = requestHead.StartLine.Split(' ');
        if (parts.Length < 3 || !Uri.TryCreate(parts[1], UriKind.Absolute, out Uri? uri))
        {
            _log.Http($"Could not parse request line: {requestHead.StartLine}");
            return;
        }

        string method = parts[0];
        string host = uri.Host;
        int port = uri.IsDefaultPort ? 80 : uri.Port;
        string originForm = uri.PathAndQuery;

        _log.Http($"{method} {uri}  ->  connecting to {host}:{port}");

        using var origin = new TcpClient();
        await origin.ConnectAsync(host, port, ct);
        _log.Step(Leg.ProxyToOrigin, 0, $"TCP established to {host}:{port}");

        await using NetworkStream originStream = origin.GetStream();

        // Forward the rewritten request head, then relay in both directions until close.
        byte[] head = requestHead.ToForwardedBytes($"{method} {originForm} {parts[2]}", stripAcceptEncoding: _injection.Enabled);
        await originStream.WriteAsync(head, ct);

        await RelayWithResponseLogAsync(browser, originStream, ct);
    }

    /// <summary>
    /// Copies browser->origin (any request body) and origin->browser (the response)
    /// at the same time. The response head is peeked first so the status line can be
    /// logged, then forwarded (possibly tampered with).
    /// </summary>
    private async Task RelayWithResponseLogAsync(Stream browser, Stream origin, CancellationToken ct)
    {
        Task requestBody = CopyAsync(browser, origin, ct);

        HttpHead? response = await HttpHead.ReadAsync(origin, ct);
        if (response is not null)
        {
            _log.Http($"response: {response.StartLine}");
            await ForwardResponseAsync(response, origin, browser, _injection, _log, ct);
        }

        try { await requestBody; } catch { /* the request side often ends first */ }
    }

    /// <summary>
    /// Sends the origin's response on to the browser. If injection is enabled and the
    /// response is plain HTML, the whole body is buffered, the marker text is spliced
    /// in, the Content-Length is corrected and the edited body is sent. Otherwise the
    /// response simply streams through unchanged.
    /// </summary>
    internal static async Task ForwardResponseAsync(
        HttpHead response, Stream origin, Stream browser, ContentInjection injection, StepLogger log, CancellationToken ct)
    {
        if (injection.Enabled && ResponseInjector.CanInject(response))
        {
            byte[] body = await ResponseInjector.ReadBodyAsync(origin, response, ct);
            byte[] tampered = ResponseInjector.Inject(body, injection.Marker);

            await browser.WriteAsync(ResponseInjector.BuildHead(response, tampered.Length), ct);
            await browser.WriteAsync(tampered, ct);
            await browser.FlushAsync(ct);

            log.Http($"** INJECTED \"{injection.Marker}\" into HTML body ({body.Length} -> {tampered.Length} bytes) **");
            return;
        }

        await browser.WriteAsync(ReserialiseVerbatim(response), ct);
        await CopyAsync(origin, browser, ct);
    }

    internal static byte[] ReserialiseVerbatim(HttpHead head)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append(head.StartLine).Append("\r\n");
        foreach (string line in head.HeaderLines)
            sb.Append(line).Append("\r\n");
        sb.Append("\r\n");
        return System.Text.Encoding.ASCII.GetBytes(sb.ToString());
    }

    internal static async Task CopyAsync(Stream from, Stream to, CancellationToken ct)
    {
        byte[] buffer = new byte[16384];
        try
        {
            while (true)
            {
                int read = await from.ReadAsync(buffer, ct);
                if (read == 0)
                    break;
                await to.WriteAsync(buffer.AsMemory(0, read), ct);
                await to.FlushAsync(ct);
            }
        }
        catch (IOException) { /* peer closed; normal end of a relay */ }
        catch (OperationCanceledException) { }
    }
}
