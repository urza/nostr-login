using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace NostrAuth.Tests;

public class LoginFlowTests
{
    private static readonly NostrKey User = NostrKey.Generate();

    [Fact]
    public async Task Full_login_sets_cookie_with_pubkey()
    {
        await using var app = await TestApp.StartAsync();
        var browser = app.NewBrowser();

        var page = await browser.OpenLoginPageAsync();
        Assert.Equal("http://localhost/signin-nostr", page.Url);
        Assert.Equal(27235, page.Kind);

        var login = await browser.SubmitAsync(page, page.Template().Sign(User));
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.Equal("/me", login.Headers.Location!.ToString());

        var me = await browser.GetAsync("/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal(User.PublicKeyHex, await me.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Replay_with_stolen_cookie_and_state_fails()
    {
        await using var app = await TestApp.StartAsync();
        var browser = app.NewBrowser();
        var page = await browser.OpenLoginPageAsync();
        var signed = page.Template().Sign(User);
        // An attacker who copied everything, including the correlation cookie.
        var stolenCookies = new CookieContainer();
        foreach (Cookie c in browser.Cookies.GetAllCookies()) stolenCookies.Add(c);

        Assert.Equal(HttpStatusCode.Redirect, (await browser.SubmitAsync(page, signed)).StatusCode);

        var attacker = app.NewBrowser();
        attacker.Cookies = stolenCookies;
        var replay = await attacker.SubmitAsync(page, signed);
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Contains("Challenge is expired or already used.", await replay.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Event_signed_for_another_site_fails()
    {
        await using var app = await TestApp.StartAsync();
        var browser = app.NewBrowser();
        var page = await browser.OpenLoginPageAsync();
        // A phishing site shows our challenge but asks the user to sign for its own URL.
        var phished = Nip98.CreateTemplate("https://evil.test/signin-nostr", "POST", DateTimeOffset.UtcNow, page.Challenge).Sign(User);

        var r = await browser.SubmitAsync(page, phished);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("URL tag does not match.", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Challenge_from_another_login_fails()
    {
        await using var app = await TestApp.StartAsync();
        var browser = app.NewBrowser();
        var page = await browser.OpenLoginPageAsync();
        var other = await app.NewBrowser().OpenLoginPageAsync();

        var r = await browser.SubmitAsync(page, other.Template().Sign(User));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("Challenge does not match.", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Other_browser_without_correlation_cookie_fails()
    {
        await using var app = await TestApp.StartAsync();
        var page = await app.NewBrowser().OpenLoginPageAsync();

        // Login CSRF: the attacker makes the victim's browser submit the attacker's signed login.
        var r = await app.NewBrowser().SubmitAsync(page, page.Template().Sign(User));
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("Correlation failed.", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Old_event_fails()
    {
        await using var app = await TestApp.StartAsync();
        var browser = app.NewBrowser();
        var page = await browser.OpenLoginPageAsync();

        var r = await browser.SubmitAsync(page, page.Template(DateTimeOffset.UtcNow.AddMinutes(-10)).Sign(User));
        Assert.Contains("Event is too old.", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Tampered_state_shows_error_page()
    {
        await using var app = await TestApp.StartAsync();
        var r = await app.NewBrowser().GetAsync("/signin-nostr?state=abc");
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        Assert.Contains("invalid or expired", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Public_origin_is_used_for_the_url_tag_but_the_form_posts_to_a_relative_path()
    {
        await using var app = await TestApp.StartAsync(o => o.PublicOrigin = "https://app.example.com");
        var browser = app.NewBrowser();
        var page = await browser.OpenLoginPageAsync();
        Assert.Equal("https://app.example.com/signin-nostr", page.Url);
        // The browser here talks to http://localhost, like a browser behind a TLS proxy talks to a
        // different scheme than the app sees. The POST must still land on this app.
        Assert.Equal("/signin-nostr", page.Path);
        Assert.Equal(HttpStatusCode.Redirect, (await browser.SubmitAsync(page, page.Template().Sign(User))).StatusCode);
    }

    [Fact]
    public async Task Public_origin_without_a_scheme_is_rejected()
    {
        // A typo in Nostr__PublicOrigin. Options are validated when the first request resolves them.
        await using var app = await TestApp.StartAsync(o => o.PublicOrigin = "app.example.com");
        var e = await Assert.ThrowsAsync<InvalidOperationException>(() => app.NewBrowser().GetAsync("/me"));
        Assert.Contains("PublicOrigin", e.Message);
    }
}

public class Nip98HandlerTests
{
    private static readonly NostrKey User = NostrKey.Generate();

    private static HttpRequestMessage Request(HttpMethod method, NostrEvent signed, byte[]? body = null)
    {
        var request = new HttpRequestMessage(method, "http://localhost/api/me");
        request.Headers.Authorization = AuthenticationHeaderValue.Parse(Nip98.ToAuthorizationHeader(signed));
        if (body is not null) request.Content = new ByteArrayContent(body) { Headers = { ContentType = new("application/json") } };
        return request;
    }

    [Fact]
    public async Task Valid_header_authenticates_and_replay_fails()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.NewApiClient();
        var signed = Nip98.CreateTemplate("http://localhost/api/me", "GET", DateTimeOffset.UtcNow).Sign(User);

        var ok = await client.SendAsync(Request(HttpMethod.Get, signed));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(Nip19.ToNpub(User.PublicKeyHex), await ok.Content.ReadAsStringAsync());

        var replay = await client.SendAsync(Request(HttpMethod.Get, signed));
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task Two_honest_requests_in_the_same_second_both_pass()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.NewApiClient();
        var now = DateTimeOffset.UtcNow;
        // Same pubkey, time, tags and content: the same event id. Only the signatures differ.
        var first = Nip98.CreateTemplate("http://localhost/api/me", "GET", now).Sign(User);
        var second = Nip98.CreateTemplate("http://localhost/api/me", "GET", now).Sign(User);
        Assert.Equal(first.Id, second.Id);

        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Request(HttpMethod.Get, first))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Request(HttpMethod.Get, second))).StatusCode);
    }

    [Fact]
    public async Task No_header_gets_401_with_scheme()
    {
        await using var app = await TestApp.StartAsync();
        var r = await app.NewApiClient().GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.Equal("Nostr", r.Headers.WwwAuthenticate.Single().Scheme);
    }

    [Fact]
    public async Task Body_must_match_payload_tag()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.NewApiClient();
        var body = Encoding.UTF8.GetBytes("{\"x\":1}");

        var good = Nip98.CreateTemplate("http://localhost/api/me", "POST", DateTimeOffset.UtcNow, body: body).Sign(User);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Request(HttpMethod.Post, good, body))).StatusCode);

        var swapped = Nip98.CreateTemplate("http://localhost/api/me", "POST", DateTimeOffset.UtcNow, body: body).Sign(User);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Post, swapped, Encoding.UTF8.GetBytes("{\"x\":2}")))).StatusCode);

        var missing = Nip98.CreateTemplate("http://localhost/api/me", "POST", DateTimeOffset.UtcNow).Sign(User);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Post, missing, body))).StatusCode);
    }

    [Fact]
    public async Task Body_without_length_headers_is_still_checked()
    {
        await using var app = await TestApp.StartAsync();
        var signedFor = Encoding.UTF8.GetBytes("{\"x\":1}");
        var evt = Nip98.CreateTemplate("http://localhost/api/me", "POST", DateTimeOffset.UtcNow, body: signedFor).Sign(User);

        // HTTP/2 shape: a body, but neither Content-Length nor Transfer-Encoding.
        var context = await app.Server.SendAsync(c =>
        {
            c.Request.Method = "POST";
            c.Request.Path = "/api/me";
            c.Request.Headers.Authorization = Nip98.ToAuthorizationHeader(evt);
            c.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"x\":2}"));
        });
        Assert.Null(context.Request.ContentLength);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
    }

    [Fact]
    public async Task Wrong_method_or_url_fails()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.NewApiClient();
        var post = Nip98.CreateTemplate("http://localhost/api/me", "POST", DateTimeOffset.UtcNow).Sign(User);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Get, post))).StatusCode);
        var other = Nip98.CreateTemplate("http://localhost/api/other", "GET", DateTimeOffset.UtcNow).Sign(User);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Request(HttpMethod.Get, other))).StatusCode);
    }
}
