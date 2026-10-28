using System.Text;

namespace Sslbump.Proxy;

/// <summary>
/// Minimal HTTP/1.1 message-head reader/parser: enough to log the request line
/// and status line and to rewrite a couple of headers. It reads bytes up to the
/// blank line that terminates the head, leaving the body on the stream.
/// </summary>
public sealed class HttpHead
{
    public string StartLine { get; }
    public IReadOnlyList<string> HeaderLines { get; }

    private HttpHead(string startLine, List<string> headerLines)
    {
        StartLine = startLine;
        HeaderLines = headerLines;
    }

    /// <summary>Reads one HTTP head (start line + headers) terminated by CRLF CRLF, or null at EOF.</summary>
    public static async Task<HttpHead?> ReadAsync(Stream stream, CancellationToken ct)
    {
        var raw = new List<byte>(1024);
        var window = new byte[1];

        // Read byte-by-byte until we see the "\r\n\r\n" that ends the head. Simple and
        // correct for a POC; a production proxy would buffer more aggressively.
        while (true)
        {
            int read = await stream.ReadAsync(window, ct);
            if (read == 0)
                return raw.Count == 0 ? null : throw new EndOfStreamException("Connection closed mid-head.");

            raw.Add(window[0]);

            if (EndsWithDoubleCrlf(raw))
                break;
        }

        string text = Encoding.ASCII.GetString(raw.ToArray());
        string[] lines = text.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        string startLine = lines.Length > 0 ? lines[0] : string.Empty;
        var headers = new List<string>(lines.Length);
        for (int i = 1; i < lines.Length; i++)
            headers.Add(lines[i]);

        return new HttpHead(startLine, headers);
    }

    /// <summary>
    /// Re-serialises the head for forwarding, dropping proxy-hop headers and forcing
    /// <c>Connection: close</c> so the simple pipe-until-EOF relay terminates cleanly.
    /// </summary>
    public byte[] ToForwardedBytes(string startLineOverride, bool stripAcceptEncoding = false)
    {
        var sb = new StringBuilder();
        sb.Append(startLineOverride).Append("\r\n");

        foreach (string header in HeaderLines)
        {
            if (StartsWith(header, "Proxy-Connection:") || StartsWith(header, "Connection:"))
                continue;
            // When we intend to rewrite the body we ask the origin for uncompressed
            // content, otherwise a string edit would land in the middle of gzip bytes.
            if (stripAcceptEncoding && StartsWith(header, "Accept-Encoding:"))
                continue;
            sb.Append(header).Append("\r\n");
        }

        sb.Append("Connection: close\r\n");
        sb.Append("\r\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    /// <summary>Returns the value of the named header, or null if it is absent.</summary>
    public string? GetHeader(string name)
    {
        foreach (string header in HeaderLines)
            if (StartsWith(header, name + ":"))
                return header[(name.Length + 1)..].Trim();
        return null;
    }

    private static bool StartsWith(string value, string prefix)
        => value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

    private static bool EndsWithDoubleCrlf(List<byte> bytes)
    {
        int n = bytes.Count;
        return n >= 4 && bytes[n - 4] == '\r' && bytes[n - 3] == '\n' && bytes[n - 2] == '\r' && bytes[n - 1] == '\n';
    }
}
