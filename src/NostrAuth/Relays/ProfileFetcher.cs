using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace NostrAuth.Relays;

/// <summary>Display data from the user's kind-0 metadata event.</summary>
public sealed record NostrProfile(string? Name, string? Picture, string? Nip05, bool Nip05Verified);

/// <summary>
/// Reads kind-0 profiles from public relays and checks NIP-05. The result is display data only:
/// the user can change it at any time, so an app must never use it as an account key.
/// </summary>
public sealed class ProfileFetcher(IHttpClientFactory httpClientFactory, ILogger<ProfileFetcher> logger)
{
    public async Task<NostrProfile?> FetchAsync(string pubKeyHex, IReadOnlyCollection<string> relays, TimeSpan timeout, CancellationToken ct)
    {
        if (relays.Count == 0) return null;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        var results = await Task.WhenAll(relays.Select(r => FetchFromRelayAsync(r, pubKeyHex, cts.Token)));
        // Relays can hold different versions. Kind 0 is replaceable, so the newest one wins.
        var newest = results.Where(e => e is not null).MaxBy(e => e!.CreatedAt);
        if (newest is null) return null;

        var (name, picture, nip05) = ParseMetadata(newest.Content);
        var verified = nip05 is not null && await VerifyNip05Async(nip05, pubKeyHex, cts.Token);
        return new NostrProfile(name, picture, nip05, verified);
    }

    private async Task<NostrEvent?> FetchFromRelayAsync(string relayUrl, string pubKeyHex, CancellationToken ct)
    {
        NostrEvent? best = null;
        try
        {
            await using var relay = await RelayConnection.ConnectAsync(relayUrl, ct);
            const string sub = "profile";
            await relay.SubscribeAsync(sub, new Dictionary<string, object> { ["kinds"] = new[] { 0 }, ["authors"] = new[] { pubKeyHex }, ["limit"] = 1 }, ct);

            await foreach (var msg in relay.Messages.ReadAllAsync(ct))
            {
                if (RelayConnection.IsEose(msg, sub)) break;
                var evt = RelayConnection.GetEvent(msg, sub);
                // A relay can return anything. Only a correctly signed kind 0 by this author counts.
                if (evt is { Kind: 0 } && evt.PubKey == pubKeyHex && evt.VerifySignature() && (best is null || evt.CreatedAt > best.CreatedAt))
                    best = evt;
            }
            return best;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // On timeout, keep what the relay sent before it went quiet.
            logger.LogDebug(e, "Profile fetch from {Relay} failed", relayUrl);
            return best;
        }
    }

    internal static (string? Name, string? Picture, string? Nip05) ParseMetadata(string content)
    {
        try
        {
            using var doc = JsonDocument.Parse(content);
            string? Get(string p) => doc.RootElement.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : null;
            var picture = Get("picture");
            // Only http(s) pictures. A "javascript:" URL in an <img> is harmless, but in a link it is not.
            if (picture is not null && !picture.StartsWith("https://", StringComparison.OrdinalIgnoreCase) && !picture.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                picture = null;
            return (Get("display_name") ?? Get("name"), picture, Get("nip05"));
        }
        catch (JsonException)
        {
            return (null, null, null);
        }
    }

    /// <summary>NIP-05: <c>https://domain/.well-known/nostr.json?name=local</c> must map <c>local</c> to the pubkey.</summary>
    public async Task<bool> VerifyNip05Async(string identifier, string pubKeyHex, CancellationToken ct)
    {
        var at = identifier.IndexOf('@');
        var (local, domain) = at < 0 ? ("_", identifier) : (identifier[..at], identifier[(at + 1)..]);
        if (local.Length == 0 || !Uri.CheckHostName(domain).Equals(UriHostNameType.Dns)) return false;
        try
        {
            // NIP-05 forbids redirects. The named client is registered without auto-redirect.
            var client = httpClientFactory.CreateClient(Nip05HttpClientName);
            var doc = await client.GetFromJsonAsync<JsonElement>($"https://{domain}/.well-known/nostr.json?name={Uri.EscapeDataString(local.ToLowerInvariant())}", ct);
            return doc.TryGetProperty("names", out var names)
                && names.TryGetProperty(local.ToLowerInvariant(), out var value)
                && value.GetString() == pubKeyHex;
        }
        catch (Exception e) when (e is HttpRequestException or JsonException or InvalidOperationException or OperationCanceledException or NotSupportedException)
        {
            logger.LogDebug(e, "NIP-05 check for {Identifier} failed", identifier);
            return false;
        }
    }

    internal const string Nip05HttpClientName = "NostrAuth.Nip05";
}
