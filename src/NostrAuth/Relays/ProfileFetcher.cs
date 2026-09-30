using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace NostrAuth.Relays;

/// <summary>Display data from the user's kind-0 metadata event.</summary>
public sealed record NostrProfile(string? Name, string? Picture, string? Nip05, bool Nip05Verified);

public enum ProfileFetchOutcome { Started, Found, NotFound, Failed }

/// <summary>One step of a profile lookup, for apps that show the user what happens.</summary>
/// <param name="Source">A relay URL, or <c>NIP-05</c>.</param>
public sealed record ProfileFetchStep(string Source, ProfileFetchOutcome Outcome, string? Detail = null);

/// <summary>
/// Reads kind-0 profiles from public relays and checks NIP-05. The result is display data only:
/// the user can change it at any time, so an app must never use it as an account key.
/// </summary>
public sealed class ProfileFetcher(IHttpClientFactory httpClientFactory, ILogger<ProfileFetcher> logger)
{
    public const string Nip05Source = "NIP-05";

    /// <returns>Null when no relay has a profile for this key.</returns>
    public async Task<NostrProfile?> FetchAsync(
        string pubKeyHex, IReadOnlyCollection<string> relays, TimeSpan timeout, CancellationToken ct,
        IProgress<ProfileFetchStep>? progress = null)
    {
        if (relays.Count == 0) return null;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        var results = await Task.WhenAll(relays.Select(r => FetchFromRelayAsync(r, pubKeyHex, progress, cts.Token)));
        // Relays can hold different versions. Kind 0 is replaceable, so the newest one wins.
        var newest = results.Where(e => e is not null).MaxBy(e => e!.CreatedAt);
        if (newest is null) return null;

        var (name, picture, nip05) = ParseMetadata(newest.Content);
        var verified = false;
        if (nip05 is not null)
        {
            progress?.Report(new(Nip05Source, ProfileFetchOutcome.Started, nip05));
            string detail;
            (verified, detail) = await CheckNip05Async(nip05, pubKeyHex, cts.Token);
            progress?.Report(new(Nip05Source, verified ? ProfileFetchOutcome.Found : ProfileFetchOutcome.NotFound, detail));
        }
        return new NostrProfile(name, picture, nip05, verified);
    }

    private async Task<NostrEvent?> FetchFromRelayAsync(string relayUrl, string pubKeyHex, IProgress<ProfileFetchStep>? progress, CancellationToken ct)
    {
        NostrEvent? best = null;
        progress?.Report(new(relayUrl, ProfileFetchOutcome.Started));
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
            progress?.Report(Result(relayUrl, best, null));
            return best;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            // On timeout, keep what the relay sent before it went quiet.
            logger.LogDebug(e, "Profile fetch from {Relay} failed", relayUrl);
            progress?.Report(Result(relayUrl, best, e is OperationCanceledException ? "timed out" : "not reachable"));
            return best;
        }
    }

    private static ProfileFetchStep Result(string relayUrl, NostrEvent? found, string? failure) =>
        found is not null ? new(relayUrl, ProfileFetchOutcome.Found, $"profile from {DateTimeOffset.FromUnixTimeSeconds(found.CreatedAt):yyyy-MM-dd}")
        : failure is not null ? new(relayUrl, ProfileFetchOutcome.Failed, failure)
        : new(relayUrl, ProfileFetchOutcome.NotFound, "no profile for this key");

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
    public async Task<bool> VerifyNip05Async(string identifier, string pubKeyHex, CancellationToken ct) =>
        (await CheckNip05Async(identifier, pubKeyHex, ct)).Verified;

    private async Task<(bool Verified, string Detail)> CheckNip05Async(string identifier, string pubKeyHex, CancellationToken ct)
    {
        var at = identifier.IndexOf('@');
        var (local, domain) = at < 0 ? ("_", identifier) : (identifier[..at], identifier[(at + 1)..]);
        // A dot is required: "localhost" and other single-label names are internal by definition.
        if (local.Length == 0 || !domain.Contains('.') || Uri.CheckHostName(domain) != UriHostNameType.Dns)
            return (false, "not a valid identifier");
        try
        {
            // The client comes from AddNostr: no redirects (NIP-05 forbids them) and no private
            // addresses, because the domain is user input and the request runs on our server.
            var client = httpClientFactory.CreateClient(Nip05HttpClientName);
            var doc = await client.GetFromJsonAsync<JsonElement>($"https://{domain}/.well-known/nostr.json?name={Uri.EscapeDataString(local.ToLowerInvariant())}", ct);
            var ok = doc.ValueKind == JsonValueKind.Object
                && doc.TryGetProperty("names", out var names) && names.ValueKind == JsonValueKind.Object
                && names.TryGetProperty(local.ToLowerInvariant(), out var value) && value.ValueKind == JsonValueKind.String
                && value.GetString() == pubKeyHex;
            return ok ? (true, $"{domain} confirms this key") : (false, $"{domain} does not list this key");
        }
        catch (Exception e) when (e is HttpRequestException or JsonException or InvalidOperationException or OperationCanceledException or NotSupportedException)
        {
            logger.LogDebug(e, "NIP-05 check for {Identifier} failed", identifier);
            // Keep the reason short and generic: the page shows it to the user.
            return (false, e is OperationCanceledException ? $"{domain} timed out" : $"{domain} did not answer with a valid nostr.json");
        }
    }

    internal const string Nip05HttpClientName = "NostrAuth.Nip05";
}
