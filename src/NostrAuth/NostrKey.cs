using System.Security.Cryptography;
using NBitcoin.Secp256k1;

namespace NostrAuth;

/// <summary>
/// A secp256k1 private key. A login server never holds the user's key. The server uses this type
/// only for its own throwaway NIP-46 client key, and tests and CLI demos use it as a stand-in signer.
/// </summary>
public sealed class NostrKey
{
    private readonly ECPrivKey _key;

    private NostrKey(ECPrivKey key)
    {
        _key = key;
        PublicKeyHex = Convert.ToHexStringLower(key.CreateXOnlyPubKey().ToBytes());
    }

    public string PublicKeyHex { get; }

    public static NostrKey Generate()
    {
        while (true)
        {
            // About 1 in 2^128 random values is not a valid scalar, so the loop almost never repeats.
            if (ECPrivKey.TryCreate(RandomNumberGenerator.GetBytes(32), out var key)) return new NostrKey(key);
        }
    }

    public static NostrKey FromHex(string hex) =>
        Hex.TryDecode(hex, 32, out var bytes) && ECPrivKey.TryCreate(bytes, out var key)
            ? new NostrKey(key)
            : throw new FormatException("Not a valid 32-byte hex private key.");

    /// <summary>Accepts <c>nsec1...</c> or 64-char hex.</summary>
    public static NostrKey Parse(string value) =>
        value.StartsWith("nsec1", StringComparison.Ordinal)
            ? FromHex(Nip19.Decode(value, "nsec"))
            : FromHex(value);

    public string ToHex()
    {
        Span<byte> buf = stackalloc byte[32];
        _key.WriteToSpan(buf);
        return Convert.ToHexStringLower(buf);
    }

    internal string SignHash(byte[] hash32)
    {
        // BIP-340 recommends fresh auxiliary randomness per signature.
        var sig = _key.SignBIP340(hash32, RandomNumberGenerator.GetBytes(32));
        var buf = new byte[64];
        sig.WriteToSpan(buf);
        return Convert.ToHexStringLower(buf);
    }

    /// <summary>ECDH shared x coordinate, as NIP-04 and NIP-44 need it.</summary>
    internal byte[] SharedX(string otherPubKeyHex)
    {
        if (!Hex.TryDecode(otherPubKeyHex, 32, out var x))
            throw new FormatException("Not a valid x-only public key.");
        // Nostr keys are x-only. Either y works for ECDH, because the shared x is the same
        // for P and -P. So we pick the even y (0x02 prefix).
        var compressed = new byte[33];
        compressed[0] = 0x02;
        x.CopyTo(compressed, 1);
        if (!ECPubKey.TryCreate(compressed, Context.Instance, out _, out var pub))
            throw new FormatException("Public key is not on the curve.");
        var shared = pub.GetSharedPubkey(_key).ToBytes(compressed: true);
        return shared[1..];
    }
}

internal static class Hex
{
    public static bool TryDecode(string? hex, int byteLength, out byte[] bytes)
    {
        bytes = [];
        if (hex is null || hex.Length != byteLength * 2) return false;
        try
        {
            bytes = Convert.FromHexString(hex);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static bool IsLowerHex(string? s, int byteLength) =>
        s is not null && s.Length == byteLength * 2 && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}
