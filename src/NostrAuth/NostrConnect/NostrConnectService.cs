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
    /// <summary>The last complaint from a relay (a refused event or a closed subscription). Shown with a timeout.</summary>
    internal string? RelayError { get; set; }

    /// <summary>Stops the relay work when a newer attempt replaces this one.</summary>
    internal CancellationTokenSource Stop { get; } = new();

    internal bool IsActive => Status is NostrConnectStatus.WaitingForSigner or NostrConnectStatus.WaitingForSignature;

    // What the login page shows under "Connection details": every relay with its state, the
    // signer, the request that waits for a reply, and the last events. A login that stops
    // half-way then explains itself to the user and the tester, not only to the server log.
    public sealed record RelayState(string State, string? Detail = null);
    public sealed record SignerInfo(string PubKey, string Via, long ClockOffset);
    public sealed record RequestInfo(string Method, int Copies, DateTimeOffset LastSent);
    public sealed record TimelineEntry(DateTimeOffset At, string Text);

    private const int MaxTimeline = 40;
    private readonly ConcurrentQueue<TimelineEntry> _timeline = new();
    private readonly ConcurrentDictionary<string, RelayState> _relays = new();

    /// <summary>The configured relays in their order. <see cref="Relays"/> has the state of each.</summary>
    public IReadOnlyList<string> RelayUrls { get; internal set; } = [];
    public IReadOnlyDictionary<string, RelayState> Relays => _relays;
    /// <summary>The signer's routing key, the relay its connect reply came through, and its clock offset in seconds.</summary>
    public SignerInfo? Signer { get; internal set; }
    public string? UserPubKey { get; internal set; }
    /// <summary>The request that waits for a reply, with the number of extra copies sent.</summary>
    public RequestInfo? Request { get; internal set; }
    /// <summary>The last events of the session, oldest first.</summary>
    public TimelineEntry[] Timeline => [.. _timeline];

    internal void SetRelay(string url, string state, string? detail = null) => _relays[url] = new RelayState(state, detail);

    internal void Note(DateTimeOffset at, string text)
    {
        _timeline.Enqueue(new TimelineEntry(at, text));
        while (_timeline.Count > MaxTimeline && _timeline.TryDequeue(out _)) { }
    }
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
    // How often a request without a reply goes out again (see "pending" in RunAsync): quick at
    // first, then slow. A copy every 3 s for the whole session got the server rate-limited by
    // nostr.oxtr.dev. get_public_key is answered without a prompt, and the first seconds after
    // the connect reply decide, so it is quick. sign_event shows a prompt: Amber and nsec.app
    // ignore a request id they already have, but a signer that does not would show one prompt
    // per copy, so copies are slower there.
    private const int QuickResends = 5;
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan PromptInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan SlowResendInterval = TimeSpan.FromSeconds(15);
    // A relay that did not answer is skipped for this long. relay.nsec.app was down for a day: with
    // the full connect timeout on every attempt, each QR code appeared 3 s late for everyone.
    private static readonly TimeSpan UnreachableMemory = TimeSpan.FromMinutes(1);
    private readonly ConcurrentDictionary<string, NostrConnectSession> _sessions = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _unreachableUntil = new();

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
        foreach (var old in active.Where(s => s.Challenge == challenge))
        {
            // An old attempt whose signer is connected may still get its signature: the user
            // approved it in the app while the page started over (a reload without session
            // storage, "New QR code"). It stays, and Get hands its result to the new attempt.
            if (old.Status == NostrConnectStatus.WaitingForSignature)
            {
                logger.LogInformation("Nostr Connect {Id}: a new QR code for the same login page; this attempt stays, its signer is connected", old.Id);
                continue;
            }
            logger.LogInformation("Nostr Connect {Id}: replaced by a new QR code for the same login page", old.Id);
            Cancel(old, "Replaced by a new QR code.");
        }
        if (active.Count(s => s.Challenge != challenge) >= maxActive)
        {
            logger.LogWarning("Nostr Connect: refused a new session, {Count} sessions wait for a signer (limit {Max})", active.Count, maxActive);
            return null;
        }

        // A fresh client key per attempt. It only encrypts the NIP-46 channel and is thrown away after.
        var clientKey = NostrKey.Generate();
        // The secret proves that the signer's "connect" reply answers our URI. Without it, anyone
        // who watches the relay could answer first and push their own key into this login.
        var secret = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

        // Connect first, and put only the relays that answered into the URI. In tests, Primal
        // answered only on the first relay of the URI; if that relay is down (or blocked for this
        // server), the login would hang with no error. Order stays as configured.
        // The user waits this long for the QR code when one relay is down without a TCP reset.
        // Good relays connect well under a second.
        using var connectTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        async Task<RelayConnection?> ConnectOrSkipAsync(string url)
        {
            if (_unreachableUntil.TryGetValue(url, out var until) && until > time.GetUtcNow()) return null;
            var connection = await TryConnectAsync(url, connectTimeout.Token);
            if (connection is null)
            {
                _unreachableUntil[url] = time.GetUtcNow() + UnreachableMemory;
                logger.LogWarning("Relay {Relay} is not reachable. It is left out of the QR code for {Seconds} s.", url, UnreachableMemory.TotalSeconds);
            }
            else
            {
                _unreachableUntil.TryRemove(url, out _);
            }
            return connection;
        }
        var attempts = await Task.WhenAll(relays.Select(ConnectOrSkipAsync));

        // The subscription must be on every relay before the QR code exists: the signer's connect
        // reply comes once, and kind 24133 that arrives before our REQ is gone. No "since" in the
        // filter: the client key is new, so there are no old events to skip, and "since" would
        // drop the replies of a signer whose phone clock is a few seconds behind the server.
        var filter = new Dictionary<string, object> { ["kinds"] = new[] { Kind }, ["#p"] = new[] { clientKey.PublicKeyHex } };
        var connections = new List<RelayConnection>();
        foreach (var c in attempts.OfType<RelayConnection>())
        {
            try
            {
                await c.SubscribeAsync(Sub, filter, connectTimeout.Token);
                connections.Add(c);
            }
            catch (Exception e) when (e is not OperationCanceledException || connectTimeout.IsCancellationRequested)
            {
                logger.LogWarning("Relay {Relay} did not take our subscription: {Error}. It is left out of the QR code.", c.Url, e.Message);
                await c.DisposeAsync();
            }
        }

        var query = string.Join("&",
            connections.Select(c => "relay=" + Uri.EscapeDataString(c.Url.OriginalString))
                .Append("secret=" + secret)
                .Append("perms=" + Uri.EscapeDataString($"sign_event:{template.Kind}"))
                .Append("name=" + Uri.EscapeDataString(appName))
                .Append("url=" + Uri.EscapeDataString(appUrl)));
        var uri = $"nostrconnect://{clientKey.PublicKeyHex}?{query}";

        var session = new NostrConnectSession(Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)), challenge, uri, time.GetUtcNow() + timeout) { RelayUrls = relays };
        _sessions[session.Id] = session;
        for (var i = 0; i < relays.Count; i++)
            if (attempts[i] is null) session.SetRelay(relays[i], "unreachable", "no answer, left out of the QR code");
            else session.SetRelay(relays[i], "connected");

        if (connections.Count == 0)
        {
            logger.LogWarning("Nostr Connect {Id}: no relay is reachable, the QR code cannot work", session.Id);
            Note(session, "No relay is reachable.");
            Fail(session, "No relay is reachable. Try again later.");
            return session;
        }
        // The client key is new for each session and public, so it can be logged: it is the
        // key that the signer's events are addressed to.
        logger.LogInformation("Nostr Connect {Id}: started for {AppUrl} with client key {ClientPubKey}", session.Id, appUrl, clientKey.PublicKeyHex);
        Note(session, $"Connected to {string.Join(", ", connections.Select(c => c.Url.Host))}. Waiting for the signer app to answer the QR code.");

        // Fire and forget: the session object carries the outcome, and RunAsync never throws.
        _ = RunAsync(session, clientKey, secret, template, connections, filter, timeout);
        return session;
    }

    /// <summary>
    /// The session to show for this id. When another attempt of the same login page was signed
    /// in the meantime, that one: the signed event names this page's challenge, so it logs the
    /// page in all the same, and the signer app's "signed" is not lost.
    /// </summary>
    public NostrConnectSession? Get(string id)
    {
        if (!_sessions.TryGetValue(id, out var s)) return null;
        if (s.Status == NostrConnectStatus.Signed) return s;
        var signed = _sessions.Values.FirstOrDefault(o => o.Challenge == s.Challenge && o.Status == NostrConnectStatus.Signed);
        if (signed is null) return s;
        if (s.IsActive)
        {
            Note(signed, "An older attempt of this login page was signed. Its result is used.");
            Cancel(s, "Another attempt of this login page was signed.");
        }
        return signed;
    }

    /// <summary>A line for the server log and for the "Connection details" on the login page.</summary>
    private void Note(NostrConnectSession session, string text)
    {
        logger.LogInformation("Nostr Connect {Id}: {Text}", session.Id, text);
        session.Note(time.GetUtcNow(), text);
    }

    private void RemoveExpired()
    {
        // Keep finished sessions a little longer, so a slow poll still sees the result.
        var cutoff = time.GetUtcNow() - TimeSpan.FromMinutes(5);
        foreach (var (id, s) in _sessions)
            if (s.Expires < cutoff) _sessions.TryRemove(id, out _);
    }

    private async Task RunAsync(NostrConnectSession session, NostrKey clientKey, string secret, NostrEvent template, IReadOnlyList<RelayConnection> connections, object filter, TimeSpan timeout)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(session.Stop.Token);
        cts.CancelAfter(timeout);
        var ct = cts.Token;

        var live = new ConcurrentDictionary<string, RelayConnection>();
        var incoming = Channel.CreateUnbounded<(string Relay, NostrEvent Event)>();

        // The request that waits for a reply. Kind 24133 is ephemeral: a relay does not store it,
        // so a signer that is not subscribed at that moment never sees it, and there is no second
        // chance. That happens all the time: Amber subscribes after it answers "connect", with
        // "since" set to the phone's clock; and on a phone the signer app loses its relay
        // connection as soon as the user switches back to the browser, so sign_event, sent right
        // after the get_public_key reply, arrives while nobody listens. So the pending request
        // goes out again: to every relay that (re)connects as the same event, and on a timer as a
        // fresh event (new created_at and id, same request id) until the reply comes. Signers see
        // the same request id again and ignore it (Amber: BunkerRequestUtils.addRequest; nsec.app:
        // "same reqs usually come on reconnects"), so the user gets one prompt.
        PendingRequest? pending = null;

        // The signer's clock, read from its connect reply. Our requests carry created_at at least
        // one second past it: a phone minutes ahead of the server would otherwise filter out every
        // copy with its "since" until the server's clock catches up, longer than the session lives.
        // Relays accept created_at a little in the future (strfry: 15 minutes).
        long signerClockAhead = 0;

        async Task PublishAsync(RelayConnection c, NostrEvent evt)
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

        async Task SendAsync(PendingRequest p, IEnumerable<RelayConnection> relays, bool fresh)
        {
            if (fresh || p.Event is null)
            {
                p.LastFreshCopy = time.GetUtcNow();
                if (p.Event is null || p.FreshIds) p.NextId();
                var request = JsonSerializer.Serialize(new { id = p.Id, method = p.Method, @params = p.Parameters });
                p.Event = new NostrEvent
                {
                    Kind = Kind,
                    CreatedAt = time.GetUtcNow().ToUnixTimeSeconds() + signerClockAhead + 1,
                    Tags = [["p", p.SignerPubKey]],
                    Content = Nip44.Encrypt(request, p.ConversationKey),
                }.Sign(clientKey);
            }
            // One logical request: the same event to every live relay. The signer may get it twice.
            var targets = relays.ToList();
            logger.LogDebug("Nostr Connect {Id}: {Method} request {RequestId} (copy {Copies}) as event {EventId}, created_at {CreatedAt}, to {Relays}",
                session.Id, p.Method, p.Id, p.Copies, p.Event.Id, p.Event.CreatedAt, targets.Count == 0 ? "no live relay" : string.Join(", ", targets.Select(c => c.Url.OriginalString)));
            foreach (var c in targets) await PublishAsync(c, p.Event);
            session.Request = new NostrConnectSession.RequestInfo(p.Method, p.Copies, time.GetUtcNow());
        }

        async Task<PendingRequest> RequestAsync(string signerPubKey, byte[] conversationKey, string method, string[] parameters, TimeSpan interval, bool freshIds)
        {
            var p = new PendingRequest(method, parameters, signerPubKey, conversationKey, interval, freshIds);
            pending = p;
            await SendAsync(p, live.Values, fresh: true);
            return p;
        }

        // A relay that comes (back) gets the pending request at once. See "pending" above.
        Task OnRelayLiveAsync(RelayConnection c) => pending is { } p ? SendAsync(p, [c], fresh: false) : Task.CompletedTask;

        async Task ResendLoopAsync()
        {
            try
            {
                // A short tick, and each request is timed from its own last fresh copy. A sleep
                // chosen from the request that is pending at bedtime would be wrong: sign_event
                // replaces get_public_key while the loop sleeps, and would get its first copy
                // after 0 to 3 s instead of its own interval.
                while (true)
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), ct);
                    if (pending is not { Resend: true } p) continue;
                    var interval = p.Copies >= QuickResends ? SlowResendInterval : p.Interval;
                    if (time.GetUtcNow() - p.LastFreshCopy < interval) continue;
                    p.Copies++;
                    if (p.Copies == 1) Note(session, $"No reply to {p.Method} yet. Sending it again until the signer answers.");
                    await SendAsync(p, live.Values, fresh: true);
                }
            }
            catch (OperationCanceledException)
            {
                // Session is over.
            }
        }

        var relayTasks = connections.Select(c => KeepRelayAsync(session, c.Url.OriginalString, c, subscribed: true, filter, live, incoming.Writer, OnRelayLiveAsync, ct))
            .Append(ResendLoopAsync()).ToArray();

        try
        {
            string? signerPubKey = null, userPubKey = null;
            byte[]? conversationKey = null;

            // The same reply arrives once per relay. The state checks below make duplicates harmless.
            await foreach (var (relay, evt) in incoming.Reader.ReadAllAsync(ct))
            {
                logger.LogDebug("Nostr Connect {Id}: event {EventId} kind {Kind} from {PubKey}, created_at {CreatedAt}, via {Relay}",
                    session.Id, evt.Id, evt.Kind, evt.PubKey, evt.CreatedAt, relay);
                if (evt.Kind != Kind || !evt.Tags.Any(t => t is ["p", var p, ..] && p == clientKey.PublicKeyHex))
                {
                    Note(session, $"Dropped an event of kind {evt.Kind} from {Short(evt.PubKey)} via {relay}: not addressed to this login.");
                    continue;
                }
                // Signer apps differ in small ways. Log each dropped reply with its reason,
                // or a login that "does nothing" cannot be diagnosed.
                if (!evt.VerifySignature())
                {
                    Note(session, $"Dropped an event with a bad signature from {Short(evt.PubKey)} via {relay}.");
                    continue;
                }
                var key = conversationKey ?? Nip44.ConversationKey(clientKey, evt.PubKey);
                var reply = TryReadReply(evt.Content, key);
                if (signerPubKey is not null && evt.PubKey != signerPubKey)
                {
                    // The pinned key is the key we encrypt requests to. A reply from another key is
                    // still ours when it decrypts with that key and carries a pending request id:
                    // only the signer that received the request knows the id. A signer may answer
                    // with a key other than the one that sent the connect reply, and a silent drop
                    // here looked exactly like "the signer signed, but nothing happened".
                    reply = TryReadReply(evt.Content, Nip44.ConversationKey(clientKey, evt.PubKey));
                    if (reply is null || pending is null || !pending.Answers(reply.Id))
                    {
                        Note(session, $"Dropped an event from {Short(evt.PubKey)} via {relay}: not from the connected signer {Short(signerPubKey)}, and not a reply to our request.");
                        continue;
                    }
                    Note(session, $"Reply from {Short(evt.PubKey)}, not from the connected signer key {Short(signerPubKey)}. Accepted: it answers our request.");
                }
                if (reply is null)
                {
                    // NIP-46 requires NIP-44. A signer that still answers with NIP-04 ("?iv=" in the
                    // content) can never complete this login; say so now instead of a 5-minute wait.
                    if (evt.Content.Contains("?iv=")) throw new InvalidOperationException("Your signer app uses old NIP-04 encryption, which NIP-46 no longer allows. Update the signer app.");
                    Note(session, $"Cannot decrypt a reply from {Short(evt.PubKey)} via {relay}.");
                    continue;
                }
                // Information, not Debug: a login that stops half-way is diagnosed from these lines.
                var answers = signerPubKey is null ? "connect" : pending is { } current && current.Answers(reply.Id) ? current.Method : "an unknown request";
                logger.LogDebug("Nostr Connect {Id}: reply id {ReplyId}, result length {Length}, error '{Error}'", session.Id, reply.Id, reply.Result?.Length ?? 0, reply.Error);
                Note(session, $"Reply to {answers} via {relay}" + (string.IsNullOrEmpty(reply.Error) ? "." : $": error '{reply.Error}'."));

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
                        Note(session, $"The connect reply did not carry our secret (it starts with '{reply.Result?[..Math.Min(4, reply.Result.Length)]}'). Ignored.");
                        continue;
                    }
                    signerPubKey = evt.PubKey;
                    conversationKey = key;
                    var clockOffset = evt.CreatedAt - time.GetUtcNow().ToUnixTimeSeconds();
                    signerClockAhead = Math.Max(0, clockOffset);
                    session.Signer = new NostrConnectSession.SignerInfo(signerPubKey, relay, clockOffset);
                    Note(session, $"Signer {Short(signerPubKey)} connected via {relay}. Its clock is {clockOffset:+#;-#;0} s from the server's. Asking for your public key (get_public_key).");
                    session.Status = NostrConnectStatus.WaitingForSignature;
                    await RequestAsync(signerPubKey, conversationKey, "get_public_key", [], ProbeInterval, freshIds: true);
                    continue;
                }

                if (pending is null || !pending.Answers(reply.Id)) continue;
                if (reply.Result == "auth_url")
                {
                    // The signer has the request and waits for the user. No more copies.
                    Note(session, $"The signer asks you to approve at {reply.Error}");
                    session.AuthUrl = reply.Error;
                    pending.Resend = false;
                    continue;
                }
                if (!string.IsNullOrEmpty(reply.Error)) throw new InvalidOperationException($"Signer refused: {reply.Error}");

                if (userPubKey is null)
                {
                    // Step 2: get_public_key. This is the user's identity as the signer states it.
                    if (!Hex.IsLowerHex(reply.Result?.ToLowerInvariant(), 32)) throw new InvalidOperationException("Signer returned an invalid public key.");
                    userPubKey = reply.Result!.ToLowerInvariant();
                    session.UserPubKey = userPubKey;
                    Note(session, $"Your public key is {Short(userPubKey)}. Asking the signer to sign the login (sign_event). Approve it in the signer app.");
                    session.AuthUrl = null;
                    var unsigned = new { kind = template.Kind, content = template.Content, tags = template.Tags, created_at = time.GetUtcNow().ToUnixTimeSeconds() };
                    await RequestAsync(signerPubKey, conversationKey!, "sign_event", [JsonSerializer.Serialize(unsigned)], PromptInterval, freshIds: false);
                    continue;
                }

                // Step 3: the signed login event, the actual proof. The login validation checks
                // its signature later. Here it must also come from the key that get_public_key named:
                // a signer that signs with its per-connection key would otherwise log the user in
                // as a new, unknown user each time, with no error anywhere.
                if (NostrEvent.TryParse(reply.Result) is not { } signed) throw new InvalidOperationException("Signer returned an invalid event.");
                if (signed.PubKey != userPubKey) throw new InvalidOperationException("Signer signed with a different key than it named as your public key.");

                pending = null;
                session.Request = null;
                session.SignedEventJson = reply.Result;
                session.Status = NostrConnectStatus.Signed;
                Note(session, $"Signed by {Short(userPubKey)}, login event {signed.Id[..8]}. Logging in.");
                return;
            }
        }
        catch (OperationCanceledException)
        {
            var why = session.Status == NostrConnectStatus.WaitingForSigner
                ? "Timed out: the signer app did not answer. Try a new QR code."
                : "Timed out while waiting for your approval in the signer app.";
            if (session.IsActive)
                Note(session, $"Timed out in {session.Status}" + (pending is { } p ? $", waiting for the reply to {p.Method} ({p.Copies} extra copies sent)" : "")
                    + (session.RelayError is { } r ? $". Last relay error: {r}" : "."));
            // A relay that refused our events is the likely cause, and the user cannot see the server log.
            Fail(session, session.RelayError is { } relayError ? $"{why} (Relay {relayError})" : why);
        }
        catch (Exception e)
        {
            logger.LogInformation(e, "Nostr Connect session {Id} failed", session.Id);
            Note(session, $"Failed: {e.Message}");
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
    private async Task KeepRelayAsync(NostrConnectSession session, string url, RelayConnection? connection, bool subscribed, object filter,
        ConcurrentDictionary<string, RelayConnection> live, ChannelWriter<(string Relay, NostrEvent Event)> incoming, Func<RelayConnection, Task> onLive, CancellationToken ct)
    {
        var backoff = TimeSpan.FromSeconds(1);
        while (!ct.IsCancellationRequested)
        {
            if (connection is not null)
            {
                try
                {
                    // The first connection was subscribed in StartAsync, before the QR code existed.
                    if (!subscribed) await connection.SubscribeAsync(Sub, filter, ct);
                    subscribed = false;
                    live[url] = connection;
                    backoff = TimeSpan.FromSeconds(1);
                    logger.LogDebug("Nostr Connect {Id}: subscribed on {Relay}", session.Id, url);
                    session.SetRelay(url, "listening");
                    await onLive(connection);
                    await foreach (var msg in connection.Messages.ReadAllAsync(ct))
                    {
                        if (RelayConnection.GetEvent(msg, Sub) is { } evt)
                        {
                            incoming.TryWrite((url, evt));
                        }
                        else if (RelayConnection.TryReadOk(msg, out var eventId, out var accepted, out var reason))
                        {
                            if (accepted)
                            {
                                logger.LogDebug("Nostr Connect {Id}: relay {Relay} accepted event {EventId} {Reason}", session.Id, url, eventId, reason);
                                session.SetRelay(url, "listening", "accepted our last request");
                                continue;
                            }
                            // Without this, a relay that blocks new pubkeys or rate-limits kind 24133
                            // looks exactly like a signer that never answers. One warning per reason:
                            // the copies of a request get the same answer many times.
                            var error = $"{url} refused the request: {reason}";
                            if (error != session.RelayError)
                            {
                                logger.LogWarning("Nostr Connect {Id}: relay {Relay} refused event {EventId}: {Reason}", session.Id, url, eventId, reason);
                                Note(session, $"{url} refused our request: {reason}");
                            }
                            else
                            {
                                logger.LogDebug("Nostr Connect {Id}: relay {Relay} refused event {EventId} again: {Reason}", session.Id, url, eventId, reason);
                            }
                            session.RelayError = error;
                            session.SetRelay(url, "listening", $"refused our last request: {reason}");
                        }
                        else if (RelayConnection.IsClosed(msg, Sub, out var why))
                        {
                            // The relay will not deliver to us (for example "auth-required"). A reconnect
                            // would get the same answer, so this relay is out for the rest of the session.
                            logger.LogWarning("Nostr Connect {Id}: relay {Relay} closed our subscription: {Reason}", session.Id, url, why);
                            Note(session, $"{url} closed our subscription: {why}");
                            session.RelayError = $"{url} closed the subscription: {why}";
                            session.SetRelay(url, "closed", why);
                            return;
                        }
                        else if (RelayConnection.IsAuth(msg))
                        {
                            // NIP-42. Not implemented: the login would need a signed AUTH event per relay.
                            // The subscription may still work; relays that insist answer with CLOSED.
                            Note(session, $"{url} asks for NIP-42 AUTH, which this login does not do.");
                        }
                        else if (RelayConnection.IsNotice(msg, out var text))
                        {
                            Note(session, $"Notice from {url}: {text}");
                        }
                        else if (!RelayConnection.IsEose(msg, Sub))
                        {
                            logger.LogDebug("Nostr Connect {Id}: other message from {Relay}: {Message}", session.Id, url, RelayConnection.Describe(msg));
                        }
                    }
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
                session.SetRelay(url, "reconnecting");
                Note(session, $"Lost the connection to {url}. Reconnecting.");
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
            if (connection is not null) Note(session, $"Reconnected to {url}.");
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

    private static string Short(string pubKey) => pubKey.Length > 12 ? $"{pubKey[..8]}…{pubKey[^4..]}" : pubKey;

    /// <summary>A NIP-46 request without a reply yet. See "pending" in <see cref="RunAsync"/>.</summary>
    private sealed class PendingRequest(string method, string[] parameters, string signerPubKey, byte[] conversationKey, TimeSpan interval, bool freshIds)
    {
        private readonly ConcurrentDictionary<string, byte> _ids = new();

        /// <summary>The request id of the latest copy. Each copy has its own id when <see cref="FreshIds"/> is set.</summary>
        public string Id { get; private set; } = "";
        /// <summary>True for a reply to any copy of this request.</summary>
        public bool Answers(string? replyId) => replyId is not null && _ids.ContainsKey(replyId);
        /// <summary>
        /// A new request id for each copy. Amber drops a request whose id it already holds
        /// (BunkerRequestUtils.addRequest): if the first copy got stuck in the app, every later
        /// copy with the same id would be dropped on arrival. Only for requests without a prompt;
        /// a fresh id for sign_event would open a second approval prompt.
        /// </summary>
        public bool FreshIds => freshIds;
        public string NextId()
        {
            Id = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
            _ids[Id] = 0;
            return Id;
        }
        public string Method => method;
        public string[] Parameters => parameters;
        public string SignerPubKey => signerPubKey;
        public byte[] ConversationKey => conversationKey;
        /// <summary>Time between the first fresh copies.</summary>
        public TimeSpan Interval => interval;
        /// <summary>The event that carried the request last. Sent as-is to a relay that (re)connects.</summary>
        public NostrEvent? Event { get; set; }
        /// <summary>Send fresh copies on a timer until the reply comes. Off once the signer confirms it has the request (auth_url).</summary>
        public bool Resend { get; set; } = true;
        /// <summary>Fresh copies sent so far by the timer.</summary>
        public int Copies { get; set; }
        /// <summary>When the event in <see cref="Event"/> was made. The next fresh copy is due <see cref="Interval"/> later.</summary>
        public DateTimeOffset LastFreshCopy { get; set; }
    }

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
