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

    /// <summary>Stops the relay work when a newer attempt replaces this one.</summary>
    internal CancellationTokenSource Stop { get; } = new();

    internal bool IsActive => Status is NostrConnectStatus.WaitingForSigner or NostrConnectStatus.WaitingForSignature;
}

/// <summary>
/// Server-side NIP-46 client for login. The browser needs no Nostr code: the server shows a
/// <c>nostrconnect://</c> URI, the user scans it with a signer app (Amber, Primal, nsec.app, ...),
/// and the server asks the signer to sign the login event. The signed event then goes through the
/// same validation as an event from a browser extension.
/// </summary>
/// <remarks>
/// Handshake: (1) the signer's <c>connect</c> reply must carry our one-time secret; this pins the
/// signer's pubkey, which is only a routing key. (2) <c>get_public_key</c> gives the user's pubkey.
/// (3) <c>sign_event</c> signs the login event, and its pubkey must be that user pubkey.
/// </remarks>
public sealed class NostrConnectService(ILogger<NostrConnectService> logger, TimeProvider time)
{
    public const int Kind = 24133;
    private const string Sub = "nip46";
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(15);
    private readonly ConcurrentDictionary<string, NostrConnectSession> _sessions = new();

    /// <param name="template">Unsigned login event with a <c>challenge</c> tag. Its <c>created_at</c> is replaced at signing time.</param>
    /// <returns>Null when <paramref name="maxActive"/> sessions already wait for a signer.</returns>
    public async Task<NostrConnectSession?> StartAsync(NostrEvent template, IReadOnlyList<string> relays, string appName, string appUrl, TimeSpan timeout, int maxActive)
    {
        RemoveExpired();

        // Each session holds relay connections for minutes, and anyone can open the login page.
        // So: one active attempt per login page, and a global cap. A new QR code for the same page
        // replaces the old attempt instead of returning it: after a dismissed or lost approval, a
        // rescan of the old code would be ignored, because its signer is already pinned.
        // The count is not atomic with the add below. A few sessions over the cap under a burst are acceptable.
        var challenge = template.GetTag("challenge") ?? throw new ArgumentException("Template needs a challenge tag.", nameof(template));
        var active = _sessions.Values.Where(s => s.IsActive).ToList();
        foreach (var old in active.Where(s => s.Challenge == challenge)) Cancel(old, "Replaced by a new QR code.");
        if (active.Count(s => s.Challenge != challenge) >= maxActive) return null;

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
        for (var i = 0; i < relays.Count; i++)
            if (attempts[i] is null) logger.LogWarning("Relay {Relay} is not reachable. It is left out of the QR code.", relays[i]);

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
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(session.Stop.Token);
        cts.CancelAfter(timeout);
        var ct = cts.Token;

        // No "since" in the filter: the client key is new for this session, so there are no old
        // events to skip. And with "since" the relay would drop the replies of a signer whose
        // phone clock is a few seconds behind the server.
        var filter = new Dictionary<string, object> { ["kinds"] = new[] { Kind }, ["#p"] = new[] { clientKey.PublicKeyHex } };
        var live = new ConcurrentDictionary<string, RelayConnection>();
        var incoming = Channel.CreateUnbounded<NostrEvent>();
        var relayTasks = connections.Select(c => KeepRelayAsync(session, c.Url.OriginalString, c, filter, live, incoming.Writer, ct)).ToArray();

        async Task<string> RequestAsync(string signerPubKey, byte[] conversationKey, string method, string[] parameters)
        {
            var id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
            var request = JsonSerializer.Serialize(new { id, method, @params = parameters });
            var evt = new NostrEvent
            {
                Kind = Kind,
                CreatedAt = time.GetUtcNow().ToUnixTimeSeconds(),
                Tags = [["p", signerPubKey]],
                Content = Nip44.Encrypt(request, conversationKey),
            }.Sign(clientKey);
            // One logical request: the same event to every live relay. The signer may get it twice.
            foreach (var c in live.Values)
            {
                try
                {
                    await c.PublishAsync(evt, ct);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    logger.LogInformation("Nostr Connect {Id}: publish to {Relay} failed: {Error}", session.Id, c.Url, e.Message);
                }
            }
            return id;
        }

        try
        {
            string? signerPubKey = null, userPubKey = null, pendingId = null;
            byte[]? conversationKey = null;

            // The same reply arrives once per relay. The state checks below make duplicates harmless.
            await foreach (var evt in incoming.Reader.ReadAllAsync(ct))
            {
                if (evt.Kind != Kind || !evt.Tags.Any(t => t is ["p", var p, ..] && p == clientKey.PublicKeyHex)) continue;
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
                    // NIP-46 requires NIP-44. A signer that still answers with NIP-04 ("?iv=" in the
                    // content) can never complete this login; say so now instead of a 5-minute wait.
                    if (evt.Content.Contains("?iv=")) throw new InvalidOperationException("Your signer app uses old NIP-04 encryption, which NIP-46 no longer allows. Update the signer app.");
                    logger.LogInformation("Nostr Connect {Id}: cannot decrypt a reply from {PubKey}", session.Id, evt.PubKey);
                    continue;
                }
                logger.LogDebug("Nostr Connect {Id}: reply from {PubKey}, id {ReplyId}, result length {Length}, error '{Error}'",
                    session.Id, evt.PubKey, reply.Id, reply.Result?.Length ?? 0, reply.Error);

                if (signerPubKey is null)
                {
                    // Step 1: the connect reply. Its author is the signer's routing key, which can
                    // differ from the user's key (new Amber makes one per connection).
                    if (reply.Result != secret)
                    {
                        // "ack" is the connect reply of the old NIP-46 text. It does not prove that the
                        // signer read our QR code, so this login cannot go on. Other values are ignored
                        // (a wrong guess from a third party must not end the session).
                        if (reply.Result == "ack") throw new InvalidOperationException("Your signer app did not return the connection secret (old NIP-46). Update the signer app.");
                        // Do not log the whole result: it may be our secret with a small change.
                        logger.LogInformation("Nostr Connect {Id}: connect reply without our secret (result starts '{Start}')",
                            session.Id, reply.Result?[..Math.Min(4, reply.Result.Length)]);
                        continue;
                    }
                    signerPubKey = evt.PubKey;
                    conversationKey = key;
                    session.Status = NostrConnectStatus.WaitingForSignature;
                    pendingId = await RequestAsync(signerPubKey, conversationKey, "get_public_key", []);
                    continue;
                }

                if (reply.Id != pendingId) continue;
                if (reply.Result == "auth_url")
                {
                    session.AuthUrl = reply.Error;
                    continue;
                }
                if (!string.IsNullOrEmpty(reply.Error)) throw new InvalidOperationException($"Signer refused: {reply.Error}");

                if (userPubKey is null)
                {
                    // Step 2: get_public_key. This is the user's identity as the signer states it.
                    if (!Hex.IsLowerHex(reply.Result?.ToLowerInvariant(), 32)) throw new InvalidOperationException("Signer returned an invalid public key.");
                    userPubKey = reply.Result!.ToLowerInvariant();
                    session.AuthUrl = null;
                    var unsigned = new { kind = template.Kind, content = template.Content, tags = template.Tags, created_at = time.GetUtcNow().ToUnixTimeSeconds() };
                    pendingId = await RequestAsync(signerPubKey, conversationKey!, "sign_event", [JsonSerializer.Serialize(unsigned)]);
                    continue;
                }

                // Step 3: the signed login event, the actual proof. The login validation checks
                // its signature later. Here it must also come from the key that get_public_key named:
                // a signer that signs with its per-connection key would otherwise log the user in
                // as a new, unknown user each time, with no error anywhere.
                if (NostrEvent.TryParse(reply.Result) is not { } signed) throw new InvalidOperationException("Signer returned an invalid event.");
                if (signed.PubKey != userPubKey) throw new InvalidOperationException("Signer signed with a different key than it named as your public key.");

                session.SignedEventJson = reply.Result;
                session.Status = NostrConnectStatus.Signed;
                return;
            }
        }
        catch (OperationCanceledException)
        {
            Fail(session, session.Status == NostrConnectStatus.WaitingForSigner
                ? "Timed out: the signer app did not answer. Try a new QR code."
                : "Timed out while waiting for your approval in the signer app.");
        }
        catch (Exception e)
        {
            logger.LogInformation(e, "Nostr Connect session {Id} failed", session.Id);
            Fail(session, e.Message);
        }
        finally
        {
            await cts.CancelAsync();
            await Task.WhenAll(relayTasks);
        }
    }

    /// <summary>
    /// Keeps one relay subscribed for the whole session. The user may need minutes to approve,
    /// and a relay can drop the connection in that time; replies sent through it would be lost.
    /// </summary>
    private async Task KeepRelayAsync(NostrConnectSession session, string url, RelayConnection? connection, object filter,
        ConcurrentDictionary<string, RelayConnection> live, ChannelWriter<NostrEvent> incoming, CancellationToken ct)
    {
        var backoff = TimeSpan.FromSeconds(1);
        while (!ct.IsCancellationRequested)
        {
            if (connection is not null)
            {
                try
                {
                    await connection.SubscribeAsync(Sub, filter, ct);
                    live[url] = connection;
                    backoff = TimeSpan.FromSeconds(1);
                    await foreach (var msg in connection.Messages.ReadAllAsync(ct))
                        if (RelayConnection.GetEvent(msg, Sub) is { } evt) incoming.TryWrite(evt);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    logger.LogDebug(e, "Nostr Connect {Id}: relay {Relay} failed", session.Id, url);
                }
                catch (OperationCanceledException)
                {
                    // Session is over.
                }
                finally
                {
                    live.TryRemove(new KeyValuePair<string, RelayConnection>(url, connection));
                    await connection.DisposeAsync();
                }
                if (ct.IsCancellationRequested) return;
                logger.LogInformation("Nostr Connect {Id}: lost relay {Relay}, reconnecting", session.Id, url);
            }

            try
            {
                await Task.Delay(backoff, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            backoff = backoff * 2 > MaxBackoff ? MaxBackoff : backoff * 2;
            connection = await TryConnectAsync(url, ct);
        }
    }

    private void Cancel(NostrConnectSession session, string reason)
    {
        Fail(session, reason);
        session.Stop.Cancel();
    }

    private static void Fail(NostrConnectSession session, string error)
    {
        // First outcome wins: a replaced session keeps "replaced", not the "timed out" that
        // follows from its cancellation.
        if (!session.IsActive) return;
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
            // Timeout included. Callers log what the failure means for them.
            logger.LogDebug("Cannot connect to relay {Relay}: {Error}", url, e.Message);
            return null;
        }
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
