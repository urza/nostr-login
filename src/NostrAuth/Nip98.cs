using System.Security.Cryptography;

namespace NostrAuth;

/// <summary>NIP-98 HTTP Auth rules. The login flow uses the same event shape plus a <c>challenge</c> tag.</summary>
public static class Nip98
{
    public const int Kind = 27235;
    public const string Scheme = "Nostr";

    /// <summary>Unsigned event template. The signer fills in pubkey, id and sig.</summary>
    public static NostrEvent CreateTemplate(string url, string method, DateTimeOffset now, string? challenge = null, byte[]? body = null)
    {
        var tags = new List<string[]> { new[] { "u", url }, new[] { "method", method.ToUpperInvariant() } };
        if (challenge is not null) tags.Add(["challenge", challenge]);
        if (body is { Length: > 0 }) tags.Add(["payload", Convert.ToHexStringLower(SHA256.HashData(body))]);
        return new NostrEvent { Kind = Kind, CreatedAt = now.ToUnixTimeSeconds(), Tags = tags.ToArray() };
    }

    /// <summary>Checks the signature, kind, time window, URL, method and (if given) the body hash.</summary>
    /// <returns>Null when the event is valid, else a short reason.</returns>
    public static string? Validate(
        NostrEvent evt, string expectedUrl, string expectedMethod, DateTimeOffset now,
        TimeSpan maxAge, TimeSpan maxFutureSkew, byte[]? body = null)
    {
        if (!Hex.IsLowerHex(evt.PubKey, 32)) return "Bad pubkey.";
        if (!evt.VerifySignature()) return "Bad id or signature.";
        if (evt.Kind != Kind) return $"Expected kind {Kind}.";

        var created = DateTimeOffset.FromUnixTimeSeconds(evt.CreatedAt);
        if (created < now - maxAge) return "Event is too old.";
        if (created > now + maxFutureSkew) return "Event is from the future.";

        // Exact match, as NIP-98 says. A signature made for another site fails here. This does NOT
        // stop a live phishing proxy that asks the user to sign our real URL: only the signer
        // or the user can catch that (see docs/research.md, section 8).
        if (evt.GetTag("u") != expectedUrl) return "URL tag does not match.";
        if (!string.Equals(evt.GetTag("method"), expectedMethod, StringComparison.OrdinalIgnoreCase)) return "Method tag does not match.";

        if (body is { Length: > 0 })
        {
            var payload = evt.GetTag("payload");
            if (payload is null || payload != Convert.ToHexStringLower(SHA256.HashData(body))) return "Payload hash does not match.";
        }
        return null;
    }

    /// <summary>Value for the <c>Authorization</c> header.</summary>
    public static string ToAuthorizationHeader(NostrEvent signed) =>
        $"{Scheme} {Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(signed.ToJson()))}";
}
