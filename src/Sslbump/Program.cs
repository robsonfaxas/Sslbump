using Sslbump.Certificates;
using Sslbump.Proxy;

// ---------------------------------------------------------------------------
// Sslbump - a didactic TLS-intercepting (man-in-the-middle) HTTP proxy.
//
//   browser  ->  Sslbump  ->  destination server
//
// It terminates TLS on both sides, logs every TLS 1.2 handshake step (0..10)
// and the decrypted HTTP, using only the .NET base class library (no YARP,
// no Titanium, no third-party packages).
//
//   --port <n>     port to listen on (default 8080)
//   --ca-dir <d>   where ca.pfx / ca.cer live (default: current directory)
//   --inject <s>   man-in-the-middle demo: splice this text into HTML responses
// ---------------------------------------------------------------------------

int port = GetOption(args, "--port") is { } p ? int.Parse(p) : 8080;
string caDir = GetOption(args, "--ca-dir") ?? Directory.GetCurrentDirectory();

ContentInjection injection = GetOption(args, "--inject") is { } marker
    ? new ContentInjection(Enabled: true, Marker: marker)
    : ContentInjection.Disabled;

string pfxPath = Path.Combine(caDir, "ca.pfx");
string cerPath = Path.Combine(caDir, "ca.cer");

CertificateAuthority ca = CertificateAuthority.LoadOrCreate(pfxPath, cerPath);
var leafFactory = new LeafCertificateFactory(ca);

Console.WriteLine("=== Sslbump POC ===");
Console.WriteLine($"Root CA certificate: {cerPath}");
Console.WriteLine("To make browsers trust the forged certificates, install that CA (run as admin):");
Console.WriteLine($"    certutil -addstore -f Root \"{cerPath}\"");
Console.WriteLine("Remove it afterwards with:");
Console.WriteLine("    certutil -delstore Root \"Sslbump POC Root CA\"");
if (injection.Enabled)
    Console.WriteLine($"Content injection ON: splicing \"{injection.Marker}\" into HTML responses.");
Console.WriteLine();

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

var proxy = new ProxyServer(port, leafFactory, injection);
try
{
    await proxy.RunAsync(cts.Token);
}
catch (OperationCanceledException)
{
    Console.WriteLine("Shutting down.");
}

static string? GetOption(string[] args, string name)
{
    int i = Array.IndexOf(args, name);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}
