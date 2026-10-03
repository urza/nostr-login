using System.Buffers.Binary;
using System.Numerics;

namespace NostrAuth;

/// <summary>
/// The ChaCha20 stream cipher from RFC 8439: 256-bit key, 96-bit nonce, 32-bit block counter.
/// NIP-44 needs the raw cipher without Poly1305, and .NET ships only the AEAD form, so it lives here.
/// The algorithm has no secret-dependent branches or table lookups, so this plain C# is also
/// constant time.
/// </summary>
internal static class ChaCha20
{
    /// <summary>XORs <paramref name="input"/> with the keystream. Encryption and decryption are the same call.</summary>
    public static byte[] Process(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, uint counter = 0)
    {
        if (key.Length != 32) throw new ArgumentException("Key must be 32 bytes.", nameof(key));
        if (nonce.Length != 12) throw new ArgumentException("Nonce must be 12 bytes.", nameof(nonce));

        Span<uint> state = stackalloc uint[16];
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574; // "expand 32-byte k"
        for (var i = 0; i < 8; i++) state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(4 * i)..]);
        state[12] = counter;
        for (var i = 0; i < 3; i++) state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[(4 * i)..]);

        var output = new byte[input.Length];
        Span<byte> keystream = stackalloc byte[64];
        for (var offset = 0; offset < input.Length; offset += 64)
        {
            Block(state, keystream);
            // The counter wraps after 256 GB. NIP-44 payloads are at most 64 KB, so it never does here.
            state[12]++;
            var n = Math.Min(64, input.Length - offset);
            for (var i = 0; i < n; i++) output[offset + i] = (byte)(input[offset + i] ^ keystream[i]);
        }
        return output;
    }

    private static void Block(ReadOnlySpan<uint> state, Span<byte> output)
    {
        Span<uint> x = stackalloc uint[16];
        state.CopyTo(x);
        for (var i = 0; i < 10; i++)
        {
            // Column rounds, then diagonal rounds. 10 double rounds = 20 rounds.
            QuarterRound(x, 0, 4, 8, 12);
            QuarterRound(x, 1, 5, 9, 13);
            QuarterRound(x, 2, 6, 10, 14);
            QuarterRound(x, 3, 7, 11, 15);
            QuarterRound(x, 0, 5, 10, 15);
            QuarterRound(x, 1, 6, 11, 12);
            QuarterRound(x, 2, 7, 8, 13);
            QuarterRound(x, 3, 4, 9, 14);
        }
        for (var i = 0; i < 16; i++) BinaryPrimitives.WriteUInt32LittleEndian(output[(4 * i)..], x[i] + state[i]);
    }

    private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 7);
    }
}
