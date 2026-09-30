using Microsoft.Extensions.Logging.Abstractions;
using NostrAuth.Relays;

namespace NostrAuth.Tests;

public sealed class ProfileFetcherTests : IDisposable
{
    private readonly Nak _nak = new();
    private readonly NostrKey _user = NostrKey.Generate();

    private static ProfileFetcher CreateFetcher() => new(new PlainHttpClientFactory(), NullLogger<ProfileFetcher>.Instance);

    private NostrEvent Metadata(string json, long createdAt) =>
        new NostrEvent { Kind = 0, CreatedAt = createdAt, Content = json }.Sign(_user);

    [SkippableFact]
    public async Task Newest_valid_profile_wins()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        var file = Path.GetTempFileName();
        await File.WriteAllLinesAsync(file,
        [
            Metadata("""{"name":"Old name"}""", 1_700_000_000).ToJson(),
            Metadata("""{"name":"bob","display_name":"Bob Nakamoto","picture":"https://example.com/bob.png","nip05":"bob@example.invalid"}""", 1_700_000_100).ToJson(),
        ]);
        try
        {
            var relay = await _nak.StartRelayAsync(file);
            var profile = await CreateFetcher().FetchAsync(_user.PublicKeyHex, [relay], TimeSpan.FromSeconds(5), CancellationToken.None);

            Assert.NotNull(profile);
            Assert.Equal("Bob Nakamoto", profile.Name);
            Assert.Equal("https://example.com/bob.png", profile.Picture);
            Assert.Equal("bob@example.invalid", profile.Nip05);
            // The domain does not exist, so the NIP-05 check must fail, not throw.
            Assert.False(profile.Nip05Verified);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [SkippableFact]
    public async Task Unreachable_relay_gives_null()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        var profile = await CreateFetcher().FetchAsync(_user.PublicKeyHex, ["ws://127.0.0.1:1"], TimeSpan.FromSeconds(2), CancellationToken.None);
        Assert.Null(profile);
    }

    [Theory]
    [InlineData("""{"name":"a","picture":"javascript:alert(1)"}""", "a", null)]
    [InlineData("""{"name":"a","display_name":"","picture":"http://x/p.png"}""", "a", "http://x/p.png")]
    [InlineData("""{"name":42}""", null, null)]
    [InlineData("not json", null, null)]
    public void Metadata_parsing_is_defensive(string content, string? name, string? picture)
    {
        var (n, p, _) = ProfileFetcher.ParseMetadata(content);
        Assert.Equal(name, n);
        Assert.Equal(picture, p);
    }

    public void Dispose() => _nak.Dispose();

    private sealed class PlainHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(3) };
    }
}

public class PublicOnlyHttpHandlerTests
{
    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.16.0.1", false)]
    [InlineData("172.32.0.1", true)]
    [InlineData("192.168.1.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("::ffff:127.0.0.1", false)]
    [InlineData("1.1.1.1", true)]
    [InlineData("2606:4700:4700::1111", true)]
    public void Only_public_addresses_pass(string ip, bool expected) =>
        Assert.Equal(expected, NostrAuth.Relays.PublicOnlyHttpHandler.IsPublic(System.Net.IPAddress.Parse(ip)));

    [Fact]
    public async Task Name_that_resolves_to_loopback_is_refused()
    {
        // "localhost" resolves to 127.0.0.1 / ::1. The handler checks the resolved address.
        using var client = new HttpClient(NostrAuth.Relays.PublicOnlyHttpHandler.Create());
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync("http://localhost:1/"));
    }
}
