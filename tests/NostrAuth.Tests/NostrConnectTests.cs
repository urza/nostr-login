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

        // The same page may replace its own attempt: that does not count against the cap.
        var first = await (await browser.PostFormAsync(page.ConnectPath!, new() { ["state"] = page.State })).Content.ReadFromJsonAsync<StartResponse>();
        var again = await browser.PostFormAsync(page.ConnectPath!, new() { ["state"] = page.State });
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.NotEqual(first!.Id, (await again.Content.ReadFromJsonAsync<StartResponse>())!.Id);

        var other = app.NewBrowser();
        var otherPage = await other.OpenLoginPageAsync();
        var refused = await other.PostFormAsync(otherPage.ConnectPath!, new() { ["state"] = otherPage.State });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, refused.StatusCode);
    }

    // --- Signer behaviour (FakeSigner) ------------------------------------------------------

    private static async Task<(TestApp.Browser Browser, TestApp.LoginPageConfig Page, StartResponse Session)> ShowQrAsync(TestApp app)
    {
        var browser = app.NewBrowser();
        var page = await browser.OpenLoginPageAsync();
        var session = await ShowQrAsync(browser, page);
        return (browser, page, session);
    }

    private static async Task<StartResponse> ShowQrAsync(TestApp.Browser browser, TestApp.LoginPageConfig page) =>
        (await (await browser.PostFormAsync(page.ConnectPath!, new() { ["state"] = page.State })).Content.ReadFromJsonAsync<StartResponse>())!;

    private static async Task<PollResponse> WaitForResultAsync(TestApp.Browser browser, TestApp.LoginPageConfig page, string id)
    {
        PollResponse? poll = null;
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline)
        {
            poll = await (await browser.GetAsync($"{page.ConnectPath}/{id}")).Content.ReadFromJsonAsync<PollResponse>();
            if (poll!.Status is "Signed" or "Failed") return poll;
            await Task.Delay(200);
        }
        return poll!;
    }

    [SkippableFact]
    public async Task Signer_with_per_connection_key_logs_in_as_the_user()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        await using var app = await TestApp.StartAsync(o => o.NostrConnectRelays = [_relay]);
        var (browser, page, session) = await ShowQrAsync(app);

        await using var signer = new FakeSigner(_user);
        await signer.ConnectAsync(session.Uri);
        var result = await WaitForResultAsync(browser, page, session.Id);

        Assert.Equal("Signed", result.Status);
        Assert.Equal(["get_public_key", "sign_event"], signer.Methods);
        Assert.Equal(HttpStatusCode.Redirect, (await browser.SubmitAsync(page, NostrEvent.TryParse(result.Event)!)).StatusCode);
        // The identity is the user key, not the signer's routing key.
        Assert.Equal(_user.PublicKeyHex, await (await browser.GetAsync("/me")).Content.ReadAsStringAsync());

        // What the page shows under "Connection details".
        Assert.Equal(_user.PublicKeyHex, result.UserPubKey);
        Assert.Equal(signer.SignerKey.PublicKeyHex, result.Signer!.PubKey);
        Assert.Equal(_relay, result.Signer.Via);
        var relay = Assert.Single(result.Relays!);
        Assert.Equal((_relay, "listening"), (relay.Url, relay.State));
        Assert.Contains(result.Timeline!, e => e.Text.StartsWith("Signed by"));
    }

    [SkippableFact]
    public async Task Signer_with_a_clock_behind_the_server_still_works()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        await using var app = await TestApp.StartAsync(o => o.NostrConnectRelays = [_relay]);
        var (browser, page, session) = await ShowQrAsync(app);

        // A phone clock two minutes behind. A "since" filter on the subscription drops these replies.
        await using var signer = new FakeSigner(_user) { ClockSkew = TimeSpan.FromMinutes(-2) };
        await signer.ConnectAsync(session.Uri);

        Assert.Equal("Signed", (await WaitForResultAsync(browser, page, session.Id)).Status);
    }

    [SkippableFact]
    public async Task Signer_that_subscribes_after_its_connect_reply_still_gets_the_request()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        await using var app = await TestApp.StartAsync(o => o.NostrConnectRelays = [_relay]);
        var (browser, page, session) = await ShowQrAsync(app);

        // Amber answers "connect" first and subscribes for requests afterwards. Kind 24133 is not
        // stored, so the first get_public_key is lost; the server must send it again.
        await using var signer = new FakeSigner(_user) { SubscribeDelay = TimeSpan.FromSeconds(2) };
        await signer.ConnectAsync(session.Uri);

        Assert.Equal("Signed", (await WaitForResultAsync(browser, page, session.Id)).Status);
        Assert.Equal("sign_event", signer.Methods.Last());
    }

    [SkippableFact]
    public async Task Signer_with_a_clock_ahead_and_a_since_filter_still_gets_the_request()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        await using var app = await TestApp.StartAsync(o => o.NostrConnectRelays = [_relay]);
        var (browser, page, session) = await ShowQrAsync(app);

        // Amber subscribes with "since" = the phone's clock. A phone a minute ahead of the server
        // makes the relay drop every request with an older created_at. The server reads the
        // signer's clock from the connect reply and dates its requests past it, so the login does
        // not wait a minute (longer than this test allows) for the server's clock to catch up.
        await using var signer = new FakeSigner(_user) { ClockSkew = TimeSpan.FromSeconds(60), SubscribeWithSince = true };
        await signer.ConnectAsync(session.Uri);

        Assert.Equal("Signed", (await WaitForResultAsync(browser, page, session.Id)).Status);
    }

    [SkippableFact]
    public async Task Signer_that_sleeps_after_get_public_key_still_gets_sign_event()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        await using var app = await TestApp.StartAsync(o => o.NostrConnectRelays = [_relay]);
        var (browser, page, session) = await ShowQrAsync(app);

        // Same phone for browser and signer: the user switches back to the browser right after the
        // connection is approved, the signer app drops its relay connection, and sign_event (sent
        // at once after the get_public_key reply) reaches nobody. The user then opens the signer
        // app again and waits for a prompt.
        await using var signer = new FakeSigner(_user) { SleepAfterGetPublicKey = TimeSpan.FromSeconds(2) };
        await signer.ConnectAsync(session.Uri);

        Assert.Equal("Signed", (await WaitForResultAsync(browser, page, session.Id)).Status);
        // One sign_event prompt per copy would be the duplicate-prompt problem; the fake signer
        // does not dedupe, so this also shows that the copies of sign_event are slow.
        Assert.Equal(1, signer.Methods.Count(m => m == "sign_event"));
    }

    [SkippableFact]
    public async Task Signer_that_signs_with_another_key_is_refused()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        await using var app = await TestApp.StartAsync(o => o.NostrConnectRelays = [_relay]);
        var (browser, page, session) = await ShowQrAsync(app);

        await using var signer = new FakeSigner(_user) { SignWith = NostrKey.Generate() };
        await signer.ConnectAsync(session.Uri);
        var result = await WaitForResultAsync(browser, page, session.Id);

        Assert.Equal("Failed", result.Status);
        Assert.Contains("different key", result.Error);
    }

    [SkippableFact]
    public async Task New_QR_code_replaces_the_old_attempt()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        await using var app = await TestApp.StartAsync(o => o.NostrConnectRelays = [_relay]);
        var (browser, page, first) = await ShowQrAsync(app);
        var second = await ShowQrAsync(browser, page);

        Assert.NotEqual(first.Id, second.Id);
        Assert.NotEqual(first.Uri, second.Uri);
        var old = await (await browser.GetAsync($"{page.ConnectPath}/{first.Id}")).Content.ReadFromJsonAsync<PollResponse>();
        Assert.Equal("Failed", old!.Status);
        Assert.Contains("Replaced", old.Error);

        await using var signer = new FakeSigner(_user);
        await signer.ConnectAsync(second.Uri);
        Assert.Equal("Signed", (await WaitForResultAsync(browser, page, second.Id)).Status);
    }

    [SkippableFact]
    public async Task Relay_that_drops_the_connection_is_reconnected()
    {
        Skip.If(Nak.Path is null, "nak is not installed");
        using var nak = new Nak();
        var relay = await nak.StartRelayAsync();
        await using var app = await TestApp.StartAsync(o => o.NostrConnectRelays = [relay]);
        var (browser, page, session) = await ShowQrAsync(app);

        // The relay goes away while the user still looks for the phone, then comes back.
        var port = nak.StopRelay();
        await Task.Delay(500);
        await nak.StartRelayAsync(port: port);
        await Task.Delay(TimeSpan.FromSeconds(4)); // backoff 1 s, then 2 s

        await using var signer = new FakeSigner(_user);
        await signer.ConnectAsync(session.Uri);
        Assert.Equal("Signed", (await WaitForResultAsync(browser, page, session.Id)).Status);
    }

    private sealed record StartResponse(string Id, string Uri, string QrSvg);
    private sealed record PollResponse(string Status, string? AuthUrl, string? Event, string? Error,
        SignerInfo? Signer, string? UserPubKey, RelayInfo[]? Relays, TimelineEntry[]? Timeline);
    private sealed record SignerInfo(string PubKey, string Via, long ClockOffset);
    private sealed record RelayInfo(string Url, string State, string? Detail);
    private sealed record TimelineEntry(long At, string Text);

    public Task DisposeAsync()
    {
        _nak.Dispose();
        var config = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".config", "nak", "bunker", _profile);
        if (File.Exists(config)) File.Delete(config);
        return Task.CompletedTask;
    }
}
