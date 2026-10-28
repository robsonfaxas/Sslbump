using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sslbump.Certificates;

/// <summary>A forged leaf certificate plus the RSA key the proxy signs with during the handshake.</summary>
/// <param name="Certificate">The leaf, signed by our CA, carrying the requested host in its SAN.</param>
/// <param name="PrivateKey">The leaf's RSA private key (used to sign the ServerKeyExchange in step 4).</param>
public sealed record ForgedCertificate(X509Certificate2 Certificate, RSA PrivateKey);

/// <summary>
/// Mints one TLS server certificate per host on demand, each signed by our
/// <see cref="CertificateAuthority"/>. Results are cached so the same host is
/// only forged once per run.
/// </summary>
public sealed class LeafCertificateFactory
{
    private readonly CertificateAuthority _ca;
    private readonly ConcurrentDictionary<string, ForgedCertificate> _cache = new(StringComparer.OrdinalIgnoreCase);

    public LeafCertificateFactory(CertificateAuthority ca) => _ca = ca;

    /// <summary>Returns a certificate valid for <paramref name="host"/>, forging and caching it if needed.</summary>
    public ForgedCertificate GetFor(string host)
        => _cache.GetOrAdd(host, Forge);

    private ForgedCertificate Forge(string host)
    {
        // Each leaf gets its own fresh RSA key pair.
        var leafKey = RSA.Create(2048);

        var request = new CertificateRequest(
            $"CN={host}",
            leafKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // A leaf is explicitly *not* a CA.
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        // serverAuth: tells the browser this certificate is allowed to identify a TLS server.
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], critical: false));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        // Subject Alternative Name: modern browsers match the host here, not in CN.
        var san = new SubjectAlternativeNameBuilder();
        if (System.Net.IPAddress.TryParse(host, out var ip))
            san.AddIpAddress(ip);
        else
            san.AddDnsName(host);
        request.CertificateExtensions.Add(san.Build());

        DateTimeOffset now = DateTimeOffset.UtcNow;

        // A random serial number keeps each forged leaf distinct.
        byte[] serial = RandomNumberGenerator.GetBytes(16);

        // Sign the leaf with the CA's private key. This is what chains the leaf back to the trusted root.
        X509Certificate2 signed = request.Create(
            _ca.Certificate,
            now.AddDays(-1),
            now.AddDays(397),   // browsers reject server certs valid for much longer than this
            serial);

        // request.Create() returns a public-only cert; attach the matching private key.
        X509Certificate2 withKey = signed.CopyWithPrivateKey(leafKey);

        return new ForgedCertificate(withKey, leafKey);
    }
}
