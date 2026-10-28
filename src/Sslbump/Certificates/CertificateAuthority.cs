using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sslbump.Certificates;

/// <summary>
/// The private certificate authority the proxy uses to forge per-site certificates.
///
/// Flow of trust once you install <c>ca.cer</c> into Windows' "Trusted Root
/// Certification Authorities" store:
///     browser trusts CA  ->  CA signs the forged leaf  ->  browser trusts the leaf.
///
/// This class only *creates* the files. Installing <c>ca.cer</c> into the trust
/// store is left to you (see the certutil command printed at start-up); the POC
/// never touches the machine trust store on its own.
/// </summary>
public sealed class CertificateAuthority
{
    private const string Subject = "CN=Sslbump POC Root CA, O=Sslbump (DO NOT TRUST), OU=Experiment";

    /// <summary>The CA certificate together with its private key. Used to sign leaf certificates.</summary>
    public X509Certificate2 Certificate { get; }

    private CertificateAuthority(X509Certificate2 certificate) => Certificate = certificate;

    /// <summary>
    /// Loads the CA from <paramref name="pfxPath"/> if it exists, otherwise creates a brand new
    /// self-signed root, writes the <c>.pfx</c> (private, used by this app) and the <c>.cer</c>
    /// (public, the one you import into the trust store).
    /// </summary>
    public static CertificateAuthority LoadOrCreate(string pfxPath, string cerPath)
    {
        if (File.Exists(pfxPath))
        {
            // X509CertificateLoader is the non-obsolete loader in modern .NET.
            var existing = X509CertificateLoader.LoadPkcs12FromFile(pfxPath, password: null);
            return new CertificateAuthority(existing);
        }

        using var caKey = RSA.Create(2048);

        var request = new CertificateRequest(
            Subject,
            caKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Mark it as a CA that is allowed to sign other certificates.
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        DateTimeOffset now = DateTimeOffset.UtcNow;
        X509Certificate2 ca = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(10));

        // ca.pfx: full key pair, read back by the proxy on the next run.
        File.WriteAllBytes(pfxPath, ca.Export(X509ContentType.Pfx));
        // ca.cer: public certificate only, this is what you import to trust the CA.
        File.WriteAllBytes(cerPath, ca.Export(X509ContentType.Cert));

        return new CertificateAuthority(ca);
    }
}
