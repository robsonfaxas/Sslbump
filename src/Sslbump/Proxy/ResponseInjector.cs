using System.Text;

namespace Sslbump.Proxy;

/// <summary>Configuration for the man-in-the-middle content tamper demo.</summary>
/// <param name="Enabled">Whether to rewrite HTML responses at all.</param>
/// <param name="Marker">The text to inject, e.g. "Robson changed it".</param>
public sealed record ContentInjection(bool Enabled, string Marker)
{
    public static readonly ContentInjection Disabled = new(false, string.Empty);
}

/// <summary>
/// The write half of the man-in-the-middle: once a response has been decrypted on
/// the origin leg, this buffers its body, splices in the marker text and rebuilds
/// the head with a corrected Content-Length, before it is re-encrypted to the
/// browser. It only touches uncompressed <c>text/html</c>; everything else
/// (images, scripts, already-gzipped bodies) is left to stream through untouched.
/// </summary>
public static class ResponseInjector
{
    /// <summary>True if this response is plain HTML we can safely edit as text.</summary>
    public static bool CanInject(HttpHead response)
    {
        string contentType = response.GetHeader("Content-Type") ?? string.Empty;
        string encoding = response.GetHeader("Content-Encoding") ?? "identity";

        bool isHtml = contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase);
        bool isPlain = encoding.Equals("identity", StringComparison.OrdinalIgnoreCase);
        return isHtml && isPlain;
    }

    /// <summary>Reads the complete response body, honouring Content-Length, chunked or close-delimited framing.</summary>
    public static async Task<byte[]> ReadBodyAsync(Stream origin, HttpHead response, CancellationToken ct)
    {
        if (string.Equals(response.GetHeader("Transfer-Encoding"), "chunked", StringComparison.OrdinalIgnoreCase))
            return await ReadChunkedAsync(origin, ct);

        if (int.TryParse(response.GetHeader("Content-Length"), out int length))
            return await ReadExactlyAsync(origin, length, ct);

        // No length and no chunking: the body runs until the origin closes the connection
        // (we already forced Connection: close on the request, so this terminates).
        using var buffer = new MemoryStream();
        await origin.CopyToAsync(buffer, ct);
        return buffer.ToArray();
    }

    /// <summary>Splices the marker into the HTML as a visible banner right after &lt;body&gt;.</summary>
    public static byte[] Inject(byte[] body, string marker)
    {
        string html = Encoding.UTF8.GetString(body);
        string banner =
            $"<div style=\"background:#ffeb3b;color:#000;padding:10px;font-weight:bold;" +
            $"text-align:center;font-family:sans-serif\">{marker}</div>";

        int bodyTag = html.IndexOf("<body", StringComparison.OrdinalIgnoreCase);
        if (bodyTag >= 0)
        {
            int close = html.IndexOf('>', bodyTag);
            html = close >= 0 ? html.Insert(close + 1, banner) : banner + html;
        }
        else
        {
            html = banner + html;
        }

        return Encoding.UTF8.GetBytes(html);
    }

    /// <summary>Rebuilds the response head with the new length and compression/framing headers removed.</summary>
    public static byte[] BuildHead(HttpHead response, int newContentLength)
    {
        var sb = new StringBuilder();
        sb.Append(response.StartLine).Append("\r\n");

        foreach (string header in response.HeaderLines)
        {
            if (Drop(header, "Content-Length:") || Drop(header, "Transfer-Encoding:") ||
                Drop(header, "Content-Encoding:") || Drop(header, "Connection:"))
                continue;
            sb.Append(header).Append("\r\n");
        }

        sb.Append("Content-Length: ").Append(newContentLength).Append("\r\n");
        sb.Append("Connection: close\r\n");
        sb.Append("\r\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    private static bool Drop(string header, string prefix)
        => header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

    private static async Task<byte[]> ReadExactlyAsync(Stream stream, int count, CancellationToken ct)
    {
        byte[] buffer = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset, count - offset), ct);
            if (read == 0)
                break;
            offset += read;
        }
        return offset == count ? buffer : buffer[..offset];
    }

    private static async Task<byte[]> ReadChunkedAsync(Stream stream, CancellationToken ct)
    {
        using var body = new MemoryStream();
        while (true)
        {
            string sizeLine = await ReadLineAsync(stream, ct);
            int semicolon = sizeLine.IndexOf(';');
            if (semicolon >= 0)
                sizeLine = sizeLine[..semicolon];

            if (!int.TryParse(sizeLine.Trim(), System.Globalization.NumberStyles.HexNumber, null, out int size) || size == 0)
                break;

            byte[] chunk = await ReadExactlyAsync(stream, size, ct);
            body.Write(chunk);
            await ReadLineAsync(stream, ct); // trailing CRLF after each chunk
        }
        return body.ToArray();
    }

    private static async Task<string> ReadLineAsync(Stream stream, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var one = new byte[1];
        while (true)
        {
            int read = await stream.ReadAsync(one, ct);
            if (read == 0)
                break;
            if (one[0] == '\n')
                break;
            if (one[0] != '\r')
                sb.Append((char)one[0]);
        }
        return sb.ToString();
    }
}
