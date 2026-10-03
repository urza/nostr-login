using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NostrAuth;

/// <summary>NIP-44 version 2 encryption. NIP-46 messages use it.</summary>
public static class Nip44
{
    private const byte Version = 2;
    private static readonly byte[] Salt = "nip44-v2"u8.ToArray();

    public static byte[] ConversationKey(NostrKey key, string otherPubKeyHex) =>
        HKDF.Extract(HashAlgorithmName.SHA256, key.SharedX(otherPubKeyHex), Salt);

    public static string Encrypt(string plaintext, byte[] conversationKey) =>
        Encrypt(plaintext, conversationKey, RandomNumberGenerator.GetBytes(32));

    internal static string Encrypt(string plaintext, byte[] conversationKey, byte[] nonce)
    {
        var (chachaKey, chachaNonce, hmacKey) = MessageKeys(conversationKey, nonce);
        var ciphertext = ChaCha20.Process(chachaKey, chachaNonce, Pad(plaintext));
        var mac = HMACSHA256.HashData(hmacKey, (byte[])[.. nonce, .. ciphertext]);
        return Convert.ToBase64String([Version, .. nonce, .. ciphertext, .. mac]);
    }

    public static string Decrypt(string payload, byte[] conversationKey)
    {
        if (payload.Length == 0 || payload[0] == '#') throw new CryptographicException("Unknown NIP-44 version.");
        var data = Convert.FromBase64String(payload);
        if (data.Length < 99 || data[0] != Version) throw new CryptographicException("Unknown NIP-44 version or bad length.");

        var nonce = data[1..33];
        var ciphertext = data[33..^32];
        var mac = data[^32..];
        var (chachaKey, chachaNonce, hmacKey) = MessageKeys(conversationKey, nonce);

        // Check the MAC before decryption, and in constant time.
        if (!CryptographicOperations.FixedTimeEquals(mac, HMACSHA256.HashData(hmacKey, (byte[])[.. nonce, .. ciphertext])))
            throw new CryptographicException("Invalid MAC.");

        return Unpad(ChaCha20.Process(chachaKey, chachaNonce, ciphertext));
    }

    private static (byte[] Key, byte[] Nonce, byte[] HmacKey) MessageKeys(byte[] conversationKey, byte[] nonce)
    {
        if (conversationKey.Length != 32 || nonce.Length != 32) throw new ArgumentException("Key and nonce must be 32 bytes.");
        var keys = HKDF.Expand(HashAlgorithmName.SHA256, conversationKey, 76, nonce);
        return (keys[..32], keys[32..44], keys[44..76]);
    }

    internal static int CalcPaddedLength(int unpaddedLength)
    {
        if (unpaddedLength <= 32) return 32;
        var nextPower = 1 << (int)(Math.Floor(Math.Log2(unpaddedLength - 1)) + 1);
        var chunk = nextPower <= 256 ? 32 : nextPower / 8;
        return chunk * ((unpaddedLength - 1) / chunk + 1);
    }

    private static byte[] Pad(string plaintext)
    {
        var bytes = Encoding.UTF8.GetBytes(plaintext);
        if (bytes.Length is < 1 or > 65535) throw new ArgumentException("Plaintext must be 1 to 65535 bytes.");
        var padded = new byte[2 + CalcPaddedLength(bytes.Length)];
        BinaryPrimitives.WriteUInt16BigEndian(padded, (ushort)bytes.Length);
        bytes.CopyTo(padded, 2);
        return padded;
    }

    private static string Unpad(byte[] padded)
    {
        var length = BinaryPrimitives.ReadUInt16BigEndian(padded);
        if (length == 0 || padded.Length != 2 + CalcPaddedLength(length)) throw new CryptographicException("Invalid padding.");
        return Encoding.UTF8.GetString(padded, 2, length);
    }
}
