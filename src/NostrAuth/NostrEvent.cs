using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NBitcoin.Secp256k1;
using SHA256 = System.Security.Cryptography.SHA256;

namespace NostrAuth;

/// <summary>A NIP-01 event. Hex strings are lowercase.</summary>
public sealed record NostrEvent
{
    [JsonPropertyName("id")] public string Id { get; init; } = "";
    [JsonPropertyName("pubkey")] public string PubKey { get; init; } = "";
    [JsonPropertyName("created_at")] public long CreatedAt { get; init; }
    [JsonPropertyName("kind")] public int Kind { get; init; }
    [JsonPropertyName("tags")] public string[][] Tags { get; init; } = [];
    [JsonPropertyName("content")] public string Content { get; init; } = "";
    [JsonPropertyName("sig")] public string Sig { get; init; } = "";

    /// <summary>First value of the first tag with this name, or null.</summary>
    public string? GetTag(string name) =>
        Tags.FirstOrDefault(t => t.Length >= 2 && t[0] == name)?[1];

    public string ToJson() => JsonSerializer.Serialize(this);

    /// <summary>Returns null for input that is not a JSON event object.</summary>
    public static NostrEvent? TryParse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            var evt = JsonSerializer.Deserialize<NostrEvent>(json);
            // A tag with a null element deserializes fine but breaks id computation.
            if (evt is null || evt.Tags is null || evt.Tags.Any(t => t is null || t.Any(v => v is null))) return null;
            return evt with { Content = evt.Content ?? "" };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>NIP-01 id: SHA-256 of the canonical <c>[0,pubkey,created_at,kind,tags,content]</c> array.</summary>
    public string ComputeId() => Convert.ToHexStringLower(SHA256.HashData(SerializeForId()));

    internal byte[] SerializeForId()
    {
        // System.Text.Json escapes non-ASCII and HTML characters. NIP-01 allows only a fixed
        // set of escapes, and any other escaping changes the hash. So we write the array by hand.
        var sb = new StringBuilder();
        sb.Append("[0,");
        AppendString(sb, PubKey);
        sb.Append(',').Append(CreatedAt).Append(',').Append(Kind).Append(",[");
        for (var i = 0; i < Tags.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append('[');
            for (var j = 0; j < Tags[i].Length; j++)
            {
                if (j > 0) sb.Append(',');
                AppendString(sb, Tags[i][j]);
            }
            sb.Append(']');
        }
        sb.Append("],");
        AppendString(sb, Content);
        sb.Append(']');
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static void AppendString(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default: sb.Append(c); break;
            }
        }
        sb.Append('"');
    }

    /// <summary>True when the id matches the content and the BIP-340 signature is valid.</summary>
    public bool VerifySignature()
    {
        if (!Hex.TryDecode(PubKey, 32, out var pub) || !Hex.TryDecode(Id, 32, out var id) || !Hex.TryDecode(Sig, 64, out var sig))
            return false;

        // The signature covers the id only. Without this check, any body could ride on a valid (id, sig) pair.
        if (!CryptographicOperations.FixedTimeEquals(id, SHA256.HashData(SerializeForId())))
            return false;

        return ECXOnlyPubKey.TryCreate(pub, out var xonly)
            && SecpSchnorrSignature.TryCreate(sig, out var schnorr)
            && xonly.SigVerifyBIP340(schnorr, id);
    }

    /// <summary>Sets pubkey, id and sig. Used by tests, the NIP-98 client demo and the NIP-46 client key.</summary>
    public NostrEvent Sign(NostrKey key)
    {
        var unsigned = this with { PubKey = key.PublicKeyHex };
        var id = SHA256.HashData(unsigned.SerializeForId());
        return unsigned with { Id = Convert.ToHexStringLower(id), Sig = key.SignHash(id) };
    }
}
