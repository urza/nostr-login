using System.Text.Json;
using System.Web;
using NostrAuth.Relays;

namespace NostrAuth.Tests;

/// <summary>
/// A minimal NIP-46 remote signer for tests, like Amber in its "nostrconnect://" flow. Unlike
/// nak bunker it can misbehave on purpose: a per-connection signer key, a wrong public key, or a
/// phone clock that is behind.
/// </summary>
internal sealed class FakeSigner(NostrKey user) : IAsyncDisposable
{
    private readonly CancellationTokenSource _cts = new();
    private RelayConnection? _relay;
    private Task? _loop;

    /// <summary>New Amber: a separate key per connection for the NIP-46 channel.</summary>
    public NostrKey SignerKey { get; init; } = NostrKey.Generate();

    /// <summary>The key that signs the requested events. Normally the user key.</summary>
    public NostrKey? SignWith { get; init; }

    /// <summary>The phone's clock: added to created_at of every event this signer sends, and to "since" (see <see cref="SubscribeWithSince"/>).</summary>
    public TimeSpan ClockSkew { get; init; }

    /// <summary>Amber: the subscription for requests is made this long after the connect reply, not before it.</summary>
    public TimeSpan SubscribeDelay { get; init; }

    /// <summary>Amber: the subscription filter has "since" = the phone's clock at subscribe time.</summary>
    public bool SubscribeWithSince { get; init; }

    /// <summary>
    /// A signer app on the same phone as the browser: right after it answers get_public_key the user
    /// switches back to the browser, the app loses its relay connection, and it is back this much later.
    /// </summary>
    public TimeSpan SleepAfterGetPublicKey { get; init; }

    public List<string> Methods { get; } = [];

    /// <summary>What the user does: scan the QR code and approve.</summary>
    public async Task ConnectAsync(string nostrConnectUri)
    {
        var uri = new Uri(nostrConnectUri.Replace("nostrconnect://", "http://"));
        var clientPubKey = uri.Host;
        var query = HttpUtility.ParseQueryString(uri.Query);
        var relayUrl = query.GetValues("relay")![0];
        var secret = query["secret"]!;

        _relay = await RelayConnection.ConnectAsync(relayUrl, _cts.Token);
        var key = Nip44.ConversationKey(SignerKey, clientPubKey);
        _loop = ServeAsync(clientPubKey, key);
        if (SubscribeDelay == TimeSpan.Zero) await SubscribeAsync();
        await SendAsync(clientPubKey, key, new { id = Guid.NewGuid().ToString(), result = secret });
        if (SubscribeDelay != TimeSpan.Zero)
        {
            await Task.Delay(SubscribeDelay);
            await SubscribeAsync();
        }
    }

    private Task SubscribeAsync()
    {
        var filter = new Dictionary<string, object> { ["kinds"] = new[] { 24133 }, ["#p"] = new[] { SignerKey.PublicKeyHex } };
        if (SubscribeWithSince) filter["since"] = (DateTimeOffset.UtcNow + ClockSkew).ToUnixTimeSeconds();
        return _relay!.SubscribeAsync("s", filter, _cts.Token);
    }

    private async Task ServeAsync(string clientPubKey, byte[] key)
    {
        try
        {
            await foreach (var msg in _relay!.Messages.ReadAllAsync(_cts.Token))
            {
                if (RelayConnection.GetEvent(msg, "s") is not { } evt || evt.PubKey != clientPubKey) continue;
                using var request = JsonDocument.Parse(Nip44.Decrypt(evt.Content, key));
                var id = request.RootElement.GetProperty("id").GetString();
                var method = request.RootElement.GetProperty("method").GetString()!;
                Methods.Add(method);
                object reply = method switch
                {
                    "get_public_key" => new { id, result = user.PublicKeyHex },
                    "sign_event" => new { id, result = Sign(request.RootElement.GetProperty("params")[0].GetString()!) },
                    _ => new { id, result = "", error = "not supported" },
                };
                await SendAsync(clientPubKey, key, reply);
                if (method == "get_public_key" && SleepAfterGetPublicKey != TimeSpan.Zero)
                {
                    await _relay.SendAsync(["CLOSE", "s"], _cts.Token);
                    await Task.Delay(SleepAfterGetPublicKey, _cts.Token);
                    await SubscribeAsync();
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private string Sign(string unsignedJson)
    {
        using var doc = JsonDocument.Parse(unsignedJson);
        var r = doc.RootElement;
        return new NostrEvent
        {
            Kind = r.GetProperty("kind").GetInt32(),
            CreatedAt = r.GetProperty("created_at").GetInt64(),
            Content = r.GetProperty("content").GetString()!,
            Tags = r.GetProperty("tags").Deserialize<string[][]>()!,
        }.Sign(SignWith ?? user).ToJson();
    }

    private Task SendAsync(string clientPubKey, byte[] key, object reply) =>
        _relay!.PublishAsync(new NostrEvent
        {
            Kind = 24133,
            CreatedAt = (DateTimeOffset.UtcNow + ClockSkew).ToUnixTimeSeconds(),
            Tags = [["p", clientPubKey]],
            Content = Nip44.Encrypt(JsonSerializer.Serialize(reply), key),
        }.Sign(SignerKey), _cts.Token);

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        if (_loop is not null) await _loop;
        if (_relay is not null) await _relay.DisposeAsync();
    }
}
