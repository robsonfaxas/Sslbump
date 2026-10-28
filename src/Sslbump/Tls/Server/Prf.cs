using System.Security.Cryptography;
using System.Text;

namespace Sslbump.Tls.Server;

/// <summary>
/// The TLS 1.2 Pseudo-Random Function (RFC 5246, section 5) and the two things
/// built on top of it: the master secret and the key block.
///
/// For our single cipher suite the PRF is always based on HMAC-SHA256:
///     PRF(secret, label, seed) = P_SHA256(secret, label || seed)
/// where
///     P_hash(secret, seed) = HMAC(secret, A(1)||seed) || HMAC(secret, A(2)||seed) || ...
///     A(0) = seed,  A(i) = HMAC(secret, A(i-1))
/// </summary>
public static class Prf
{
    /// <summary>Runs the PRF and returns <paramref name="length"/> bytes of output.</summary>
    public static byte[] Compute(byte[] secret, string label, ReadOnlySpan<byte> seed, int length)
    {
        byte[] labelAndSeed = new byte[label.Length + seed.Length];
        Encoding.ASCII.GetBytes(label, labelAndSeed);
        seed.CopyTo(labelAndSeed.AsSpan(label.Length));

        return PHashSha256(secret, labelAndSeed, length);
    }

    private static byte[] PHashSha256(byte[] secret, byte[] seed, int length)
    {
        using var hmac = new HMACSHA256(secret);

        var output = new byte[length];
        int filled = 0;

        // A(1) = HMAC(secret, A(0)) where A(0) = seed.
        byte[] a = hmac.ComputeHash(seed);

        while (filled < length)
        {
            // HMAC(secret, A(i) || seed)
            byte[] block = hmac.ComputeHash(Concat(a, seed));

            int take = Math.Min(block.Length, length - filled);
            Array.Copy(block, 0, output, filled, take);
            filled += take;

            // A(i+1) = HMAC(secret, A(i))
            a = hmac.ComputeHash(a);
        }

        return output;
    }

    /// <summary>
    /// master_secret = PRF(pre_master_secret, "master secret", client_random || server_random)
    /// truncated to 48 bytes. This is the classic (non extended-master-secret) derivation,
    /// chosen to match the steps in the brief.
    /// </summary>
    public static byte[] DeriveMasterSecret(byte[] preMasterSecret, byte[] clientRandom, byte[] serverRandom)
        => Compute(preMasterSecret, "master secret", Concat(clientRandom, serverRandom), 48);

    /// <summary>
    /// key_block = PRF(master_secret, "key expansion", server_random || client_random),
    /// taken as long as the cipher suite needs. Note the randoms are in the OPPOSITE
    /// order to the master-secret derivation - that ordering is part of the spec.
    /// </summary>
    public static byte[] DeriveKeyBlock(byte[] masterSecret, byte[] serverRandom, byte[] clientRandom, int length)
        => Compute(masterSecret, "key expansion", Concat(serverRandom, clientRandom), length);

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        byte[] result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}
