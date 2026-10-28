using System.Text;

namespace Sslbump.Logging;

/// <summary>
/// Which side of the man-in-the-middle a log line is talking about.
/// The proxy always has two TLS conversations going at once, so every
/// line says which leg it belongs to.
/// </summary>
public enum Leg
{
    /// <summary>Browser  ->  proxy. Here the proxy plays the role of the TLS *server*.</summary>
    BrowserToProxy,

    /// <summary>Proxy  ->  origin server. Here the proxy plays the role of the TLS *client*.</summary>
    ProxyToOrigin,
}

/// <summary>
/// Console logger whose only job is to make the handshake readable.
/// Every connection gets an id, every line is tagged with its leg and,
/// when relevant, the numbered TLS step (0..10) from the project brief.
/// </summary>
public sealed class StepLogger
{
    private static readonly object ConsoleGate = new();

    private readonly int _connectionId;

    public StepLogger(int connectionId) => _connectionId = connectionId;

    /// <summary>Logs one of the numbered handshake steps (0..10).</summary>
    public void Step(Leg leg, int step, string message)
        => Write(leg, ColorFor(leg), $"{step,2}  {message}");

    /// <summary>Logs application-level traffic (the forwarded HTTP request/response).</summary>
    public void Http(string message)
        => Write(null, ConsoleColor.White, "HTTP  " + message);

    /// <summary>Logs something that is neither a numbered step nor HTTP (e.g. errors, notes).</summary>
    public void Info(Leg leg, string message)
        => Write(leg, ColorFor(leg), "    " + message);

    public void Error(Leg leg, string message)
        => Write(leg, ConsoleColor.Red, "!!  " + message);

    /// <summary>
    /// Prints a block of key material (randoms, secrets, keys) indented so it is
    /// visually subordinate to the step that produced it.
    /// </summary>
    public void Detail(Leg leg, string label, ReadOnlySpan<byte> value)
        => Write(leg, ConsoleColor.DarkGray, $"      - {label}: {ToHex(value)}");

    public void Detail(Leg leg, string label, string value)
        => Write(leg, ConsoleColor.DarkGray, $"      - {label}: {value}");

    private void Write(Leg? leg, ConsoleColor color, string body)
    {
        string tag = leg switch
        {
            Leg.BrowserToProxy => "BROWSER->PROXY ",
            Leg.ProxyToOrigin  => "PROXY ->ORIGIN ",
            _                  => "               ",
        };

        // Lock so that the two legs of one connection never interleave mid-line.
        lock (ConsoleGate)
        {
            ConsoleColor previous = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine($"[conn#{_connectionId} {tag}] {body}");
            Console.ForegroundColor = previous;
        }
    }

    private static ConsoleColor ColorFor(Leg leg)
        => leg == Leg.BrowserToProxy ? ConsoleColor.Cyan : ConsoleColor.Yellow;

    /// <summary>Hex dump, shortened in the middle when long so the console stays readable.</summary>
    public static string ToHex(ReadOnlySpan<byte> bytes)
    {
        const int Max = 48;
        var sb = new StringBuilder();
        int shown = Math.Min(bytes.Length, Max);
        for (int i = 0; i < shown; i++)
            sb.Append(bytes[i].ToString("x2"));
        if (bytes.Length > Max)
            sb.Append($"...({bytes.Length} bytes)");
        return sb.ToString();
    }
}
