using System.Net.WebSockets;
using System.Text.Json;
using System.Threading.Channels;

namespace NostrAuth.Relays;

/// <summary>
/// One WebSocket connection to one relay. Deliberately minimal: a login needs a short-lived
/// subscription and a few publishes, not reconnects or a relay pool with outbox logic.
/// </summary>
public sealed class RelayConnection : IAsyncDisposable
{
    private const int MaxMessageBytes = 1024 * 1024;
    private readonly ClientWebSocket _socket = new();
    private readonly Channel<JsonElement[]> _incoming = Channel.CreateUnbounded<JsonElement[]>();
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly CancellationTokenSource _cts = new();
    private Task? _receiveLoop;

    private RelayConnection(Uri url) => Url = url;

    public Uri Url { get; }

    /// <summary>Relay messages (<c>["EVENT", ...]</c>, <c>["EOSE", ...]</c>, <c>["OK", ...]</c> and so on) in arrival order.</summary>
    public ChannelReader<JsonElement[]> Messages => _incoming.Reader;

    public static async Task<RelayConnection> ConnectAsync(string url, CancellationToken ct)
    {
        var relay = new RelayConnection(new Uri(url));
        try
        {
            await relay._socket.ConnectAsync(relay.Url, ct);
        }
        catch
        {
            await relay.DisposeAsync();
            throw;
        }
        relay._receiveLoop = relay.ReceiveLoopAsync();
        return relay;
    }

    public Task SubscribeAsync(string subscriptionId, object filter, CancellationToken ct) =>
        SendAsync(["REQ", subscriptionId, filter], ct);

    public Task PublishAsync(NostrEvent evt, CancellationToken ct) => SendAsync(["EVENT", evt], ct);

    public async Task SendAsync(object[] message, CancellationToken ct)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(message);
        await _sendLock.WaitAsync(ct);
        try
        {
            await _socket.SendAsync(bytes, WebSocketMessageType.Text, endOfMessage: true, ct);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private async Task ReceiveLoopAsync()
    {
        var buffer = new byte[64 * 1024];
        using var message = new MemoryStream();
        try
        {
            while (_socket.State == WebSocketState.Open && !_cts.IsCancellationRequested)
            {
                var result = await _socket.ReceiveAsync(buffer, _cts.Token);
                if (result.MessageType == WebSocketMessageType.Close) break;
                message.Write(buffer, 0, result.Count);
                // A relay is untrusted. One endless message must not eat the server's memory.
                if (message.Length > MaxMessageBytes) break;
                if (!result.EndOfMessage) continue;

                var parsed = TryParse(message.GetBuffer().AsSpan(0, (int)message.Length));
                message.SetLength(0);
                if (parsed is not null) _incoming.Writer.TryWrite(parsed);
            }
        }
        catch (Exception e) when (e is OperationCanceledException or WebSocketException)
        {
            // Relay went away or we closed it. The reader sees the completed channel.
        }
        finally
        {
            _incoming.Writer.TryComplete();
        }
    }

    private static JsonElement[]? TryParse(ReadOnlySpan<byte> utf8)
    {
        try
        {
            using var doc = JsonDocument.Parse(utf8.ToArray());
            return doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement.EnumerateArray().Select(e => e.Clone()).ToArray()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Reads the event from an <c>["EVENT", subId, event]</c> message, or returns null.</summary>
    public static NostrEvent? GetEvent(JsonElement[] message, string subscriptionId) =>
        message is [{ ValueKind: JsonValueKind.String } type, { ValueKind: JsonValueKind.String } sub, var evt]
        && type.GetString() == "EVENT" && sub.GetString() == subscriptionId
            ? NostrEvent.TryParse(evt.GetRawText())
            : null;

    public static bool IsEose(JsonElement[] message, string subscriptionId) =>
        message is [{ ValueKind: JsonValueKind.String } type, { ValueKind: JsonValueKind.String } sub, ..]
        && type.GetString() == "EOSE" && sub.GetString() == subscriptionId;

    /// <summary>Reads <c>["OK", id, accepted, reason]</c>: the relay's answer to an event that we published.</summary>
    public static bool TryReadOk(JsonElement[] message, out string eventId, out bool accepted, out string reason)
    {
        if (message is [{ ValueKind: JsonValueKind.String } type, { ValueKind: JsonValueKind.String } id, { ValueKind: JsonValueKind.True or JsonValueKind.False } ok, .. var rest]
            && type.GetString() == "OK")
        {
            eventId = id.GetString()!;
            accepted = ok.ValueKind == JsonValueKind.True;
            reason = rest is [{ ValueKind: JsonValueKind.String } r, ..] ? r.GetString()! : "";
            return true;
        }
        eventId = reason = "";
        accepted = false;
        return false;
    }

    /// <summary>True for <c>["AUTH", challenge]</c>: the relay wants NIP-42 authentication.</summary>
    public static bool IsAuth(JsonElement[] message) =>
        message is [{ ValueKind: JsonValueKind.String } type, ..] && type.GetString() == "AUTH";

    /// <summary>The message as JSON, cut to <paramref name="max"/> characters, for a log line.</summary>
    public static string Describe(JsonElement[] message, int max = 200)
    {
        var text = JsonSerializer.Serialize(message);
        return text.Length <= max ? text : text[..max] + "…";
    }

    /// <summary>True for <c>["CLOSED", subId, reason]</c>: the relay ended our subscription, for example "auth-required: ...".</summary>
    public static bool IsClosed(JsonElement[] message, string subscriptionId, out string reason)
    {
        if (message is [{ ValueKind: JsonValueKind.String } type, { ValueKind: JsonValueKind.String } sub, .. var rest]
            && type.GetString() == "CLOSED" && sub.GetString() == subscriptionId)
        {
            reason = rest is [{ ValueKind: JsonValueKind.String } r, ..] ? r.GetString()! : "";
            return true;
        }
        reason = "";
        return false;
    }

    /// <summary>True for <c>["NOTICE", text]</c>, a human-readable message from the relay.</summary>
    public static bool IsNotice(JsonElement[] message, out string text)
    {
        if (message is [{ ValueKind: JsonValueKind.String } type, { ValueKind: JsonValueKind.String } t, ..] && type.GetString() == "NOTICE")
        {
            text = t.GetString()!;
            return true;
        }
        text = "";
        return false;
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_socket.State == WebSocketState.Open)
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await _socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, timeout.Token);
            }
            catch (Exception e) when (e is OperationCanceledException or WebSocketException)
            {
                // Best effort. The relay drops the connection on its own anyway.
            }
        }
        if (_receiveLoop is not null) await _receiveLoop;
        _socket.Dispose();
        _cts.Dispose();
        _sendLock.Dispose();
    }
}
