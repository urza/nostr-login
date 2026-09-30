namespace NostrAuth.Tests;

public class Nip98Tests
{
    private const string Url = "https://app.test/signin-nostr";
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
    private static readonly NostrKey Key = NostrKey.Generate();

    private static string? Validate(NostrEvent signed, byte[]? body = null) =>
        Nip98.Validate(signed, Url, "POST", Now, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(1), body);

    private static NostrEvent Signed(DateTimeOffset? at = null, string url = Url, string method = "POST", byte[]? body = null) =>
        Nip98.CreateTemplate(url, method, at ?? Now, "c", body).Sign(Key);

    [Fact] public void Valid_event_passes() => Assert.Null(Validate(Signed()));
    [Fact] public void Method_is_case_insensitive() => Assert.Null(Validate(Signed(method: "post")));
    [Fact] public void Old_event_fails() => Assert.Equal("Event is too old.", Validate(Signed(Now.AddMinutes(-6))));
    [Fact] public void Future_event_fails() => Assert.Equal("Event is from the future.", Validate(Signed(Now.AddMinutes(2))));
    [Fact] public void Other_site_fails() => Assert.Equal("URL tag does not match.", Validate(Signed(url: "https://evil.test/signin-nostr")));
    [Fact] public void Other_method_fails() => Assert.Equal("Method tag does not match.", Validate(Signed(method: "GET")));

    [Fact]
    public void Wrong_kind_fails()
    {
        var note = (Signed() with { Kind = 1 }).Sign(Key);
        Assert.Equal("Expected kind 27235.", Validate(note));
    }

    [Fact]
    public void Forged_signature_fails()
    {
        var other = NostrKey.Generate();
        // Claim the key of someone else, keep our own signature.
        Assert.NotNull(Validate(Signed() with { PubKey = other.PublicKeyHex }));
    }

    [Fact]
    public void Body_hash_is_checked()
    {
        byte[] body = "{\"a\":1}"u8.ToArray();
        Assert.Null(Validate(Signed(body: body), body));
        Assert.Equal("Payload hash does not match.", Validate(Signed(body: body), "{\"a\":2}"u8.ToArray()));
    }
}
