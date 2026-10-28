using System.Security.Cryptography;
using Sslbump.Logging;

namespace Sslbump.Tls.Records;

/// <summary>
/// Pulls the interesting fields out of the clear-text handshake messages purely
/// for logging. Nothing here affects the protocol; it just makes the console
/// output show the randoms, the chosen cipher, the SNI and the certificate hash
/// the brief asks for.
/// </summary>
public static class HandshakeDetails
{
    public static void LogClientHello(StepLogger log, Leg leg, ReadOnlySpan<byte> body)
    {
        var r = new TlsReader(body);

        ushort version = r.ReadUInt16();
        ReadOnlySpan<byte> random = r.ReadBytes(32);
        r.ReadVector8();                     // session_id
        ReadOnlySpan<byte> cipherSuites = r.ReadVector16();

        log.Detail(leg, "max version", DescribeVersion(version));
        log.Detail(leg, "client random", random);
        log.Detail(leg, "offered cipher suites", $"{cipherSuites.Length / 2} suites");

        string? sni = TryReadSni(ref r);
        if (sni is not null)
            log.Detail(leg, "SNI (requested host)", sni);
    }

    public static void LogServerHello(StepLogger log, Leg leg, ReadOnlySpan<byte> body)
    {
        var r = new TlsReader(body);

        ushort version = r.ReadUInt16();
        ReadOnlySpan<byte> random = r.ReadBytes(32);
        r.ReadVector8();                     // session_id
        ushort cipher = r.ReadUInt16();

        log.Detail(leg, "chosen version", DescribeVersion(version));
        log.Detail(leg, "server random", random);
        log.Detail(leg, "chosen cipher", $"0x{cipher:X4}");
    }

    public static void LogCertificate(StepLogger log, Leg leg, ReadOnlySpan<byte> body)
    {
        var r = new TlsReader(body);

        int listLength = r.ReadUInt24();
        if (listLength <= 0)
            return;

        // The first certificate in the list is the leaf (the server's own cert).
        int certLength = r.ReadUInt24();
        ReadOnlySpan<byte> leafDer = r.ReadBytes(certLength);

        // SHA-256 over the DER bytes: this is the hash the browser recomputes and
        // compares against the CA-signed value when it validates the certificate.
        byte[] hash = SHA256.HashData(leafDer);
        log.Detail(leg, "leaf certificate bytes", $"{certLength} bytes DER");
        log.Detail(leg, "SHA-256 of leaf cert", hash);
    }

    private static string? TryReadSni(ref TlsReader r)
    {
        if (r.Remaining < 2)
            return null;

        r.ReadVector8();                     // compression_methods
        if (r.Remaining < 2)
            return null;

        r.ReadUInt16();                      // total extensions length (we just walk to the end)

        while (r.Remaining >= 4)
        {
            ushort extType = r.ReadUInt16();
            ReadOnlySpan<byte> extData = r.ReadVector16();

            if (extType == 0x0000) // server_name
            {
                var inner = new TlsReader(extData);
                inner.ReadUInt16();          // server_name_list length
                inner.ReadUInt8();           // name_type == host_name(0)
                ReadOnlySpan<byte> host = inner.ReadVector16();
                return System.Text.Encoding.ASCII.GetString(host);
            }
        }

        return null;
    }

    private static string DescribeVersion(ushort version) => version switch
    {
        0x0303 => "TLS 1.2",
        0x0302 => "TLS 1.1",
        0x0301 => "TLS 1.0",
        0x0304 => "TLS 1.3",
        _      => $"0x{version:X4}",
    };
}
