using System.Net;
using System.Net.Sockets;
using Sslbump.Certificates;
using Sslbump.Logging;

namespace Sslbump.Proxy;

/// <summary>
/// The front door: a TCP listener on the proxy port (default 8080). For every
/// browser connection it reads the first HTTP request line and routes it:
///   - <c>CONNECT host:443</c>  ->  <see cref="ConnectTunnel"/> (HTTPS, man-in-the-middle)
///   - anything else            ->  <see cref="HttpForwarder"/> (plain HTTP on port 80)
///
/// Configure the browser (or the OS) to use <c>localhost:&lt;port&gt;</c> as its
/// HTTP and HTTPS proxy, and all its traffic arrives here.
/// </summary>
public sealed class ProxyServer
{
    private readonly int _port;
    private readonly LeafCertificateFactory _leafFactory;
    private readonly ContentInjection _injection;
    private int _nextConnectionId;

    public ProxyServer(int port, LeafCertificateFactory leafFactory, ContentInjection injection)
    {
        _port = port;
        _leafFactory = leafFactory;
        _injection = injection;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var listener = new TcpListener(IPAddress.Loopback, _port);
        listener.Start();
        Console.WriteLine($"Sslbump proxy listening on http://localhost:{_port}  (Ctrl+C to stop)");
        Console.WriteLine();

        while (!ct.IsCancellationRequested)
        {
            TcpClient client = await listener.AcceptTcpClientAsync(ct);
            int id = Interlocked.Increment(ref _nextConnectionId);

            // One task per connection; failures are contained to that connection.
            _ = Task.Run(() => HandleConnectionAsync(client, id, ct), ct);
        }
    }

    private async Task HandleConnectionAsync(TcpClient client, int id, CancellationToken ct)
    {
        var log = new StepLogger(id);
        try
        {
            using (client)
            await using (NetworkStream browser = client.GetStream())
            {
                log.Step(Leg.BrowserToProxy, 0, $"TCP established from {client.Client.RemoteEndPoint}");

                HttpHead? head = await HttpHead.ReadAsync(browser, ct);
                if (head is null)
                    return;

                if (head.StartLine.StartsWith("CONNECT ", StringComparison.Ordinal))
                    await new ConnectTunnel(log, _leafFactory, _injection).HandleAsync(head, browser, ct);
                else
                    await new HttpForwarder(log, _injection).HandleAsync(head, browser, ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            log.Error(Leg.BrowserToProxy, $"{ex.GetType().Name}: {ex.Message}");
        }
    }
}
