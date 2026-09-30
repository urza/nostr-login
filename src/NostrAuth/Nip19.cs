namespace NostrAuth;

/// <summary>NIP-19 bech32 for the simple 32-byte entities (<c>npub</c>, <c>nsec</c>).</summary>
public static class Nip19
{
    private const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    public static string ToNpub(string pubKeyHex) => Encode("npub", pubKeyHex);

    /// <summary>Accepts <c>npub1...</c> or 64-char hex. Returns lowercase hex.</summary>
    public static string NormalizePubKey(string value) =>
        value.StartsWith("npub1", StringComparison.OrdinalIgnoreCase)
            ? Decode(value, "npub")
            : Hex.TryDecode(value, 32, out var b) ? Convert.ToHexStringLower(b) : throw new FormatException("Not a valid public key.");

    public static string Encode(string hrp, string hex)
    {
        var data = ConvertBits(Convert.FromHexString(hex), 8, 5, pad: true);
        var checksum = CreateChecksum(hrp, data);
        return hrp + "1" + string.Concat(data.Concat(checksum).Select(v => Charset[v]));
    }

    /// <summary>Decodes and checks the checksum and prefix. Returns lowercase hex.</summary>
    public static string Decode(string bech32, string expectedHrp)
    {
        var s = bech32.ToLowerInvariant();
        var sep = s.LastIndexOf('1');
        if (sep < 1 || s.Length - sep < 7) throw new FormatException("Not a bech32 string.");
        var hrp = s[..sep];
        if (hrp != expectedHrp) throw new FormatException($"Expected '{expectedHrp}', got '{hrp}'.");
        var values = s[(sep + 1)..].Select(c => Charset.IndexOf(c)).ToArray();
        if (values.Any(v => v < 0)) throw new FormatException("Invalid bech32 character.");
        if (Polymod(ExpandHrp(hrp).Concat(values).ToArray()) != 1) throw new FormatException("Bad bech32 checksum.");
        var bytes = ConvertBits(values[..^6], 5, 8, pad: false);
        if (bytes.Length != 32) throw new FormatException("Expected a 32-byte payload.");
        return Convert.ToHexStringLower(bytes.Select(v => (byte)v).ToArray());
    }

    private static int[] CreateChecksum(string hrp, int[] data)
    {
        var values = ExpandHrp(hrp).Concat(data).Concat(new int[6]).ToArray();
        var mod = Polymod(values) ^ 1;
        return Enumerable.Range(0, 6).Select(i => (mod >> (5 * (5 - i))) & 31).ToArray();
    }

    private static int[] ExpandHrp(string hrp) =>
        hrp.Select(c => c >> 5).Append(0).Concat(hrp.Select(c => c & 31)).ToArray();

    private static int Polymod(int[] values)
    {
        int[] gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        var chk = 1;
        foreach (var v in values)
        {
            var top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (var i = 0; i < 5; i++)
                if (((top >> i) & 1) != 0) chk ^= gen[i];
        }
        return chk;
    }

    private static int[] ConvertBits(IEnumerable<int> data, int from, int to, bool pad)
    {
        var acc = 0;
        var bits = 0;
        var result = new List<int>();
        var maxv = (1 << to) - 1;
        // Keep only the bits still needed, or the accumulator overflows on long inputs.
        var maxAcc = (1 << (from + to - 1)) - 1;
        foreach (var value in data)
        {
            acc = ((acc << from) | value) & maxAcc;
            bits += from;
            while (bits >= to)
            {
                bits -= to;
                result.Add((acc >> bits) & maxv);
            }
        }
        if (pad && bits > 0) result.Add((acc << (to - bits)) & maxv);
        else if (!pad && (bits >= from || ((acc << (to - bits)) & maxv) != 0)) throw new FormatException("Invalid bech32 padding.");
        return result.ToArray();
    }

    private static int[] ConvertBits(byte[] data, int from, int to, bool pad) =>
        ConvertBits(data.Select(b => (int)b), from, to, pad);
}
