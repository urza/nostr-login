using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using NostrAuth.Relays;

namespace NostrAuth.NostrConnect;

public enum NostrConnectStatus { WaitingForSigner, WaitingForSignature, Signed, Failed }

/// <summary>One login attempt through a NIP-46 remote signer. The browser polls it by <see cref="Id"/>.</summary>
public sealed class NostrConnectSession
{
    internal NostrConnectSession(string id, string challenge, string uri, DateTimeOffset expires)
    {
        Id = id;
        Challenge = challenge;
        ConnectUri = uri;
        Expires = expires;
    }

    public string Id { get; }
    internal string Challenge { get; }
    public string ConnectUri { get; }
    public DateTimeOffset Expires { get; }
    public NostrConnectStatus Status { get; internal set; } = NostrConnectStatus.WaitingForSigner;
    /// <summary>Set when the signer asks the user to approve on a web page (NIP-46 <c>auth_url</c>).</summary>
    public string? AuthUrl { get; internal set; }
    public string? SignedEventJson { get; internal set; }
    public string? Error { get; internal set; }
}

/// <summary>
/// Server-side NIP-46 client for login. The browser needs no Nostr code: the server shows a
/// <c>nostrconnect://</c> URI, the user scans it with a signer app (Amber, nsec.app, ...), and the
/// server asks the signer to sign the login event. The signed event then goes through the same
/// validation as an event from a browser extension.
/// </summary>
public sealed class NostrConnectService(ILogger<NostrConnectService> logger, TimeProvider time)
{
    public const int Kind = 24133;
    private readonly ConcurrentDictionary<string, NostrConnectSession> _sessions = new();

    /// <param name="template">Unsigned login event with a <c>challenge</c> tag. Its <c>created_at</c> is replaced at signing time.</param>
    /// <returns>Null when <paramref name="maxActive"/> sessions already wait for a signer.</returns>
    public async Task<NostrConnectSession?> StartAsync(NostrEvent template, IReadOnlyList<string> relays, string appName, string appUrl, TimeSpan timeout, int maxActive)
    {
        RemoveExpired();

        // Each session holds relay connections for minutes, and anyone can open the login page.
        // So: one session per login page (a second click gets the same QR code), and a global cap.
        // The count is not atomic with the add below. A few sessions over the cap under a burst are acceptable.
        var challenge = template.GetTag("challenge") ?? throw new ArgumentException("Template needs a challenge tag.", nameof(template));
        var active = _sessions.Values.Where(s => s.Status is NostrConnectStatus.WaitingForSigner or NostrConnectStatus.WaitingForSignature).ToList();
        if (active.FirstOrDefault(s => s.Challenge == challenge) is { } existing) return existing;
        if (active.Count >= maxActive) return null;

        // A fresh client key per attempt. It only encrypts the NIP-46 channel and is thrown away after.
        var clientKey = NostrKey.Generate();
        // The secret proves that the signer's "connect" reply answers our URI. Without it, anyone
        // who watches the relay could answer first and push their own key into this login.
        var secret = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

        // Connect first, and put only the relays that answered into the URI. In tests, Primal
        // answered only on the first relay of the URI; if that relay is down (or blocked for this
        // server), the login would hang with no error. Order stays as configured.
        using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var attempts = await Task.WhenAll(relays.Select(u => TryConnectAsync(u, connectTimeout.Token)));
        var connections = attempts.OfType<RelayConnection>().ToList();

        var query = string.Join("&",
            connections.Select(c => "relay=" + Uri.EscapeDataString(c.Url.OriginalString))
                .Append("secret=" + secret)
                .Append("perms=" + Uri.EscapeDataString($"sign_event:{template.Kind}"))
                .Append("name=" + Uri.EscapeDataString(appName))
                .Append("url=" + Uri.EscapeDataString(appUrl)));
        var uri = $"nostrconnect://{clientKey.PublicKeyHex}?{query}";

        var session = new NostrConnectSession(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)), challenge, uri, time.GetUtcNow() + timeout);
        _sessions[session.Id] = session;

        if (connections.Count == 0)
        {
            Fail(session, "No relay is reachable. Try again later.");
            return session;
        }

        // Fire and forget: the session object carries the outcome, and RunAsync never throws.
        _ = RunAsync(session, clientKey, secret, template, connections, timeout);
        return session;
    }

    public NostrConnectSession? Get(string id) => _sessions.TryGetValue(id, out var s) ? s : null;

    private void RemoveExpired()
    {
        // Keep finished sessions a little longer, so a slow poll still sees the result.
        var cutoff = time.GetUtcNow() - TimeSpan.FromMinutes(5);
        foreach (var (id, s) in _sessions)
            if (s.Expires < cutoff) _sessions.TryRemove(id, out _);
    }

    private async Task RunAsync(NostrConnectSession session, NostrKey clientKey, string secret, NostrEvent template, IReadOnlyList<RelayConnection> connections, TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        var ct = cts.Token;
        try
        {
            const string sub = "nip46";
            var filter = new Dictionary<string, object>
            {
                ["kinds"] = new[] { Kind },
                ["#p"] = new[] { clientKey.PublicKeyHex },
                ["since"] = time.GetUtcNow().ToUnixTimeSeconds() - 10,
            };
            foreach (var c in connections) await c.SubscribeAsync(sub, filter, ct);

            // The same reply arrives once per relay. The state checks below make duplicates harmless.
            var merged = Merge(connections, ct);
            string? signerPubKey = null;
            string? signRequestId = null;
            byte[]? conversationKey = null;

            await foreach (var msg in merged.ReadAllAsync(ct))
            {
                var evt = RelayConnection.GetEvent(msg, sub);
                if (evt is null || evt.Kind != Kind) continue;
                // Signer apps differ in small ways. Log each dropped reply with its reason,
                // or a login that "does nothing" cannot be diagnosed.
                if (!evt.VerifySignature())
                {
                    logger.LogInformation("Nostr Connect {Id}: dropped event with a bad signature from {PubKey}", session.Id, evt.PubKey);
                    continue;
                }
                if (signerPubKey is not null && evt.PubKey != signerPubKey) continue;

                var key = conversationKey ?? Nip44.ConversationKey(clientKey, evt.PubKey);
                if (TryReadReply(evt.Content, key) is not { } reply)
                {
                    logger.LogInformation("Nostr Connect {Id}: cannot decrypt a reply from {PubKey} (NIP-04 signer: {Nip04})",
                        session.Id, evt.PubKey, evt.Content.Contains("?iv="));
                    continue;
                }
                logger.LogDebug("Nostr Connect {Id}: reply from {PubKey}, id {ReplyId}, result length {Length}, error '{Error}'",
                    session.Id, evt.PubKey, reply.Id, reply.Result?.Length ?? 0, reply.Error);

                if (signerPubKey is null)
                {
                    // Step 1: the signer answers the nostrconnect URI. Its pubkey can differ from
                    // the user's pubkey, so this proves nothing about the user yet.
                    if (reply.Result != secret)
                    {
                        // Do not log the whole result: it may be our secret with a small change.
                        logger.LogInformation("Nostr Connect {Id}: connect reply without our secret (result starts '{Start}')",
                            session.Id, reply.Result?[..Math.Min(4, reply.Result.Length)]);
                        continue;
                    }
                    signerPubKey = evt.PubKey;
                    conversationKey = key;
                    session.Status = NostrConnectStatus.WaitingForSignature;

                    signRequestId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
                    var unsigned = new { kind = template.Kind, content = template.Content, tags = template.Tags, created_at = time.GetUtcNow().ToUnixTimeSeconds() };
                    var request = JsonSerializer.Serialize(new { id = signRequestId, method = "sign_event", @params = new[] { JsonSerializer.Serialize(unsigned) } });
                    var requestEvent = new NostrEvent
                    {
                        Kind = Kind,
                        CreatedAt = time.GetUtcNow().ToUnixTimeSeconds(),
                        Tags = [["p", signerPubKey]],
                        Content = Nip44.Encrypt(request, conversationKey),
                    }.Sign(clientKey);
                    foreach (var c in connections) await c.PublishAsync(requestEvent, ct);
                    continue;
                }

                // Step 2: the reply to sign_event. This is the actual proof.
                if (reply.Id != signRequestId) continue;
                if (reply.Result == "auth_url")
                {
                    session.AuthUrl = reply.Error;
                    continue;
                }
                if (!string.IsNullOrEmpty(reply.Error)) throw new InvalidOperationException($"Signer refused: {reply.Error}");
                if (NostrEvent.TryParse(reply.Result) is null) throw new InvalidOperationException("Signer returned an invalid event.");

                session.SignedEventJson = reply.Result;
                session.Status = NostrConnectStatus.Signed;
                return;
            }
            throw new InvalidOperationException("All relay connections closed.");
        }
        catch (OperationCanceledException)
        {
            Fail(session, "Timed out while waiting for the signer.");
        }
        catch (Exception e)
        {
            logger.LogInformation(e, "Nostr Connect session {Id} failed", session.Id);
            Fail(session, e.Message);
        }
        finally
        {
            await cts.CancelAsync();
            foreach (var c in connections) await c.DisposeAsync();
        }
    }

    private static void Fail(NostrConnectSession session, string error)
    {
        session.Error = error;
        session.Status = NostrConnectStatus.Failed;
    }

    private async Task<RelayConnection?> TryConnectAsync(string url, CancellationToken ct)
    {
        try
        {
            return await RelayConnection.ConnectAsync(url, ct);
        }
        catch (Exception e)
        {
            // Timeout included: a relay that is slow to connect is left out of the QR code.
            logger.LogWarning(e, "Cannot connect to relay {Relay}", url);
            return null;
        }
    }

    private static ChannelReader<JsonElement[]> Merge(IReadOnlyList<RelayConnection> connections, CancellationToken ct)
    {
        var merged = Channel.CreateUnbounded<JsonElement[]>();
        var pumps = connections.Select(async c =>
        {
            try
            {
                await foreach (var m in c.Messages.ReadAllAsync(ct)) merged.Writer.TryWrite(m);
            }
            catch (OperationCanceledException)
            {
                // Session is over.
            }
        }).ToArray();
        _ = Task.WhenAll(pumps).ContinueWith(_ => merged.Writer.TryComplete(), TaskScheduler.Default);
        return merged.Reader;
    }

    private sealed record Reply(string? Id, string? Result, string? Error);

    private static Reply? TryReadReply(string content, byte[] conversationKey)
    {
        try
        {
            using var doc = JsonDocument.Parse(Nip44.Decrypt(content, conversationKey));
            string? Get(string p) => doc.RootElement.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            return new Reply(Get("id"), Get("result"), Get("error"));
        }
        catch (Exception e) when (e is CryptographicException or FormatException or JsonException or ArgumentException)
        {
            // Not for us, or an old NIP-04 signer. NIP-46 now requires NIP-44.
            return null;
        }
    }
}
