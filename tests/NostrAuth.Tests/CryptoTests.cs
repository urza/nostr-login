using System.Security.Cryptography;
using System.Text.Json;

namespace NostrAuth.Tests;

public class NostrEventTests
{
    public static TheoryData<string> RealEvents()
    {
        var data = new TheoryData<string>();
        foreach (var line in File.ReadLines("Vectors/real-events.jsonl").Where(l => l.Length > 0)) data.Add(line);
        return data;
    }

    [Theory]
    [MemberData(nameof(RealEvents))]
    public void Real_events_from_relays_verify(string json)
    {
        var evt = NostrEvent.TryParse(json)!;
        Assert.Equal(evt.Id, evt.ComputeId());
        Assert.True(evt.VerifySignature());
    }

    [Theory]
    // Signed by nostr-tools (the JS library most browser signers use). Content has \n \r \t \f \b,
    // quotes, backslash, HTML, emoji and Czech letters. No other control characters: nostr-tools
    // escapes those as \u00XX, but NIP-01 says "verbatim" (checked 2026-09-29, nostr-tools 2.25.2).
    [InlineData("Vectors/nostr-tools-escaping.json")]
    // Signed by nak (go-nostr). Without \f and \b: nak escapes those as \u000c and \u0008 when it
    // computes the id, which disagrees with NIP-01 and nostr-tools (checked 2026-09-29, nak v0.20.7).
    [InlineData("Vectors/nak-escaping.json")]
    public void Id_matches_other_implementations_for_characters_that_need_escaping(string file)
    {
        var evt = NostrEvent.TryParse(File.ReadAllText(file))!;
        Assert.Equal(evt.Id, evt.ComputeId());
        Assert.True(evt.VerifySignature());
    }

    [Fact]
    public void Changed_content_fails()
    {
        var evt = NostrEvent.TryParse(File.ReadAllText("Vectors/nostr-tools-escaping.json"))!;
        Assert.False((evt with { Content = evt.Content + "!" }).VerifySignature());
        Assert.False((evt with { CreatedAt = evt.CreatedAt + 1 }).VerifySignature());
        Assert.False((evt with { Tags = [] }).VerifySignature());
    }

    [Fact]
    public void Id_and_sig_from_other_event_fail()
    {
        var key = NostrKey.Generate();
        var a = new NostrEvent { Kind = 1, Content = "a", CreatedAt = 1 }.Sign(key);
        var b = new NostrEvent { Kind = 1, Content = "b", CreatedAt = 1 }.Sign(key);
        Assert.False((b with { Id = a.Id, Sig = a.Sig }).VerifySignature());
        Assert.False((b with { Sig = a.Sig }).VerifySignature());
    }

    [Fact]
    public void Sign_then_verify_round_trips_through_json()
    {
        var key = NostrKey.Generate();
        var signed = new NostrEvent { Kind = 27235, Content = "", CreatedAt = 1_800_000_000, Tags = [["u", "https://x.test/a?b=c"]] }.Sign(key);
        var parsed = NostrEvent.TryParse(signed.ToJson())!;
        Assert.Equal(key.PublicKeyHex, parsed.PubKey);
        Assert.True(parsed.VerifySignature());
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[1,2]")]
    [InlineData("{\"tags\":[[null]]}")]
    [InlineData("{\"tags\":null}")]
    public void TryParse_rejects_junk(string json) => Assert.Null(NostrEvent.TryParse(json));

    [Fact]
    public void Garbage_hex_fails_verification_without_exception()
    {
        var evt = new NostrEvent { Id = "zz", PubKey = new string('0', 64), Sig = new string('1', 128) };
        Assert.False(evt.VerifySignature());
    }
}

public class Nip19Tests
{
    // Examples from the NIP-19 document.
    private const string Npub = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";
    private const string PubHex = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
    private const string Nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
    private const string SecHex = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa";

    [Fact] public void Encodes_npub() => Assert.Equal(Npub, Nip19.ToNpub(PubHex));
    [Fact] public void Decodes_npub() => Assert.Equal(PubHex, Nip19.Decode(Npub, "npub"));
    [Fact] public void Decodes_nsec() => Assert.Equal(SecHex, NostrKey.Parse(Nsec).ToHex());
    [Fact] public void Normalizes_hex_and_npub() => Assert.Equal(PubHex, Nip19.NormalizePubKey(PubHex.ToUpperInvariant()));

    [Fact]
    public void Rejects_bad_checksum() =>
        Assert.Throws<FormatException>(() => Nip19.Decode(Npub[..^1] + (Npub[^1] == 'q' ? 'p' : 'q'), "npub"));

    [Fact]
    public void Rejects_wrong_prefix() => Assert.Throws<FormatException>(() => Nip19.Decode(Nsec, "npub"));
}

public class Nip44Tests
{
    private static readonly JsonElement V2 = JsonDocument.Parse(File.ReadAllText("Vectors/nip44.vectors.json")).RootElement.GetProperty("v2");

    private static string S(JsonElement e, string p) => e.GetProperty(p).GetString()!;

    [Fact]
    public void Conversation_keys_match_vectors()
    {
        foreach (var v in V2.GetProperty("valid").GetProperty("get_conversation_key").EnumerateArray())
        {
            var key = NostrKey.FromHex(S(v, "sec1"));
            Assert.Equal(S(v, "conversation_key"), Convert.ToHexStringLower(Nip44.ConversationKey(key, S(v, "pub2"))));
        }
    }

    [Fact]
    public void Encrypt_and_decrypt_match_vectors()
    {
        foreach (var v in V2.GetProperty("valid").GetProperty("encrypt_decrypt").EnumerateArray())
        {
            var sec1 = NostrKey.FromHex(S(v, "sec1"));
            var sec2 = NostrKey.FromHex(S(v, "sec2"));
            var ck = Nip44.ConversationKey(sec1, sec2.PublicKeyHex);
            Assert.Equal(S(v, "conversation_key"), Convert.ToHexStringLower(ck));
            // The key is symmetric: the other side derives the same one.
            Assert.Equal(ck, Nip44.ConversationKey(sec2, sec1.PublicKeyHex));

            var payload = Nip44.Encrypt(S(v, "plaintext"), ck, Convert.FromHexString(S(v, "nonce")));
            Assert.Equal(S(v, "payload"), payload);
            Assert.Equal(S(v, "plaintext"), Nip44.Decrypt(payload, ck));
        }
    }

    [Fact]
    public void Padded_lengths_match_vectors()
    {
        foreach (var v in V2.GetProperty("valid").GetProperty("calc_padded_len").EnumerateArray())
            Assert.Equal(v[1].GetInt32(), Nip44.CalcPaddedLength(v[0].GetInt32()));
    }

    [Fact]
    public void Invalid_payloads_are_rejected()
    {
        foreach (var v in V2.GetProperty("invalid").GetProperty("decrypt").EnumerateArray())
        {
            var ck = Convert.FromHexString(S(v, "conversation_key"));
            var ex = Record.Exception(() => Nip44.Decrypt(S(v, "payload"), ck));
            Assert.True(ex is CryptographicException or FormatException, $"{S(v, "note")}: got {ex?.GetType().Name ?? "no exception"}");
        }
    }

    [Fact]
    public void Invalid_keys_are_rejected()
    {
        foreach (var v in V2.GetProperty("invalid").GetProperty("get_conversation_key").EnumerateArray())
        {
            var ex = Record.Exception(() => Nip44.ConversationKey(NostrKey.FromHex(S(v, "sec1")), S(v, "pub2")));
            Assert.IsType<FormatException>(ex);
        }
    }
}
