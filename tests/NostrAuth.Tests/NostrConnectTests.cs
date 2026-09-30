using System.Net;
using System.Net.Http.Json;

namespace NostrAuth.Tests;

/// <summary>
/// End-to-end NIP-46 test with real processes: <c>nak serve</c> is the relay and <c>nak bunker</c>
/// plays the signer app (Amber, nsec.app). Skipped when nak is not installed.
/// </summary>
public sealed class NostrConnectTests : IAsyncLifetime
{
    private readonly Nak _nak = new();
    private readonly NostrKey _user = NostrKey.Generate();
    private readonly string _profile = "nostrauth-test-" + Guid.NewGuid().ToString("N")[..8];
    private string _relay = "";

    public async Task InitializeAsync()
    {
        if (Nak.Path is null) return;
        _relay = await _nak.StartRelayAsync();
        // --persist + --profile let "nak bunker connect" hand the nostrconnect URI to this running bunker.
        _nak.Start("bunker", "--persist", "--profile", _profile, "--sec", _user.ToHex(), _relay);
        await Task.Delay(1000);
    }
    [SkippableFact]
    public async Task Login_through_remote_signer()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        await using var app = await TestApp.StartAsync(o => o.NostrConnectRelays = [_relay]);
        var browser = app.NewBrowser();
        var page = await browser.OpenLoginPageAsync();
        Assert.NotNull(page.ConnectPath);

        // What the "Show QR code" button does.
        var start = await browser.PostFormAsync(page.ConnectPath!, new() { ["state"] = page.State });
        var session = (await start.Content.ReadFromJsonAsync<StartResponse>())!;
        Assert.StartsWith("nostrconnect://", session.Uri);
        Assert.Contains("<svg", session.QrSvg);

        // What the user does: scan the QR code with the signer app.
        _nak.Start("bunker", "connect", "--profile", _profile, session.Uri);

        PollResponse? poll = null;
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline)
        {
            poll = await (await browser.GetAsync($"{page.ConnectPath}/{session.Id}")).Content.ReadFromJsonAsync<PollResponse>();
            if (poll!.Status is "Signed" or "Failed") break;
            await Task.Delay(300);
        }
        Assert.Equal("Signed", poll?.Status);

        // The page submits the event exactly like an extension-signed one.
        var signed = NostrEvent.TryParse(poll!.Event)!;
        Assert.Equal(_user.PublicKeyHex, signed.PubKey);
        var login = await browser.SubmitAsync(page, signed);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Equal(_user.PublicKeyHex, await (await browser.GetAsync("/me")).Content.ReadAsStringAsync());
    }

    [SkippableFact]
    public async Task Unknown_session_is_404()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        await using var app = await TestApp.StartAsync(o => o.NostrConnectRelays = [_relay]);
        var r = await app.NewBrowser().GetAsync("/signin-nostr/connect/doesnotexist");
        Assert.Equal(HttpStatusCode.NotFound, r.StatusCode);
    }

    [SkippableFact]
    public async Task Dead_relay_is_left_out_of_the_QR_code()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        // Port 1 refuses connections: a relay that is down, listed first.
        await using var app = await TestApp.StartAsync(o => o.NostrConnectRelays = ["ws://127.0.0.1:1", _relay]);
        var browser = app.NewBrowser();
        var page = await browser.OpenLoginPageAsync();
        var session = (await (await browser.PostFormAsync(page.ConnectPath!, new() { ["state"] = page.State })).Content.ReadFromJsonAsync<StartResponse>())!;

        Assert.DoesNotContain(Uri.EscapeDataString("ws://127.0.0.1:1"), session.Uri);
        Assert.Contains("relay=" + Uri.EscapeDataString(_relay), session.Uri);
    }

    [SkippableFact]
    public async Task No_reachable_relay_fails_with_a_message()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        await using var app = await TestApp.StartAsync(o => o.NostrConnectRelays = ["ws://127.0.0.1:1"]);
        var browser = app.NewBrowser();
        var page = await browser.OpenLoginPageAsync();
        var session = (await (await browser.PostFormAsync(page.ConnectPath!, new() { ["state"] = page.State })).Content.ReadFromJsonAsync<StartResponse>())!;
        var poll = await (await browser.GetAsync($"{page.ConnectPath}/{session.Id}")).Content.ReadFromJsonAsync<PollResponse>();

        Assert.Equal("Failed", poll!.Status);
        Assert.Contains("No relay is reachable", poll.Error);
    }

    [SkippableFact]
    public async Task Sessions_are_limited()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        await using var app = await TestApp.StartAsync(o =>
        {
            o.NostrConnectRelays = [_relay];
            o.MaxNostrConnectSessions = 1;
        });
        var browser = app.NewBrowser();
        var page = await browser.OpenLoginPageAsync();

        var first = await (await browser.PostFormAsync(page.ConnectPath!, new() { ["state"] = page.State })).Content.ReadFromJsonAsync<StartResponse>();
        var again = await (await browser.PostFormAsync(page.ConnectPath!, new() { ["state"] = page.State })).Content.ReadFromJsonAsync<StartResponse>();
        Assert.Equal(first!.Id, again!.Id);

        var other = app.NewBrowser();
        var otherPage = await other.OpenLoginPageAsync();
        var refused = await other.PostFormAsync(otherPage.ConnectPath!, new() { ["state"] = otherPage.State });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, refused.StatusCode);
    }

    private sealed record StartResponse(string Id, string Uri, string QrSvg);
    private sealed record PollResponse(string Status, string? AuthUrl, string? Event, string? Error);

    public Task DisposeAsync()
    {
        _nak.Dispose();
        var config = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config", "nak", "bunker", _profile);
        if (File.Exists(config)) File.Delete(config);
        return Task.CompletedTask;
    }
}
