using System.Net;
using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NostrAuth.Authentication;

namespace NostrAuth.Tests;

/// <summary>A minimal app with cookie + Nostr login and a NIP-98 API, on an in-memory TestServer.</summary>
internal sealed partial class TestApp : IAsyncDisposable
{
    private readonly WebApplication _app;

    private TestApp(WebApplication app) => _app = app;

    public static async Task<TestApp> StartAsync(Action<NostrLoginOptions>? configure = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddAuthentication(o =>
            {
                o.DefaultScheme = "Cookies";
                o.DefaultChallengeScheme = NostrLoginDefaults.AuthenticationScheme;
            })
            .AddCookie("Cookies")
            .AddNostr(o =>
            {
                o.AppName = "Test app";
                o.ProfileRelays = [];
                o.NostrConnectRelays = [];
                configure?.Invoke(o);
            })
            .AddNostrHttpAuth();
        builder.Services.AddAuthorization();

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/me", (ClaimsPrincipal u) => u.FindFirstValue(ClaimTypes.NameIdentifier)).RequireAuthorization();
        app.MapMethods("/api/me", ["GET", "POST"], (ClaimsPrincipal u) => u.FindFirstValue(NostrClaimTypes.Npub))
            .RequireAuthorization(p => p.AddAuthenticationSchemes(NostrHttpAuthDefaults.AuthenticationScheme).RequireAuthenticatedUser());
        await app.StartAsync();
        return new TestApp(app);
    }

    public Browser NewBrowser() => new(_app.GetTestServer().CreateHandler());

    public HttpClient NewApiClient() => _app.GetTestClient();

    public TestServer Server => _app.GetTestServer();

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();

    /// <summary>A tiny browser: keeps cookies, does not follow redirects, so tests can look at each step.</summary>
    internal sealed class Browser(HttpMessageHandler handler)
    {
        private readonly HttpClient _client = new(handler) { BaseAddress = new Uri("http://localhost") };
        public CookieContainer Cookies { get; set; } = new();

        public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
        {
            var uri = new Uri(_client.BaseAddress!, request.RequestUri!);
            var header = Cookies.GetCookieHeader(uri);
            if (header.Length > 0) request.Headers.Add("Cookie", header);
            var response = await _client.SendAsync(request);
            if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
                foreach (var c in setCookies) Cookies.SetCookies(uri, c);
            return response;
        }

        public Task<HttpResponseMessage> GetAsync(string url) => SendAsync(new HttpRequestMessage(HttpMethod.Get, url));

        public Task<HttpResponseMessage> PostFormAsync(string url, Dictionary<string, string> form) =>
            SendAsync(new HttpRequestMessage(HttpMethod.Post, url) { Content = new FormUrlEncodedContent(form) });

        /// <summary>Opens a protected page and follows the redirect to the login page.</summary>
        public async Task<LoginPageConfig> OpenLoginPageAsync(string protectedUrl = "/me")
        {
            var r1 = await GetAsync(protectedUrl);
            Assert.Equal(HttpStatusCode.Redirect, r1.StatusCode);
            var r2 = await GetAsync(r1.Headers.Location!.ToString());
            Assert.Equal(HttpStatusCode.OK, r2.StatusCode);
            var html = await r2.Content.ReadAsStringAsync();
            var json = ConfigRegex().Match(html).Groups[1].Value;
            return JsonSerializer.Deserialize<LoginPageConfig>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        }

        /// <summary>What the page's JavaScript does after the signer returns the event: a POST to the relative path.</summary>
        public Task<HttpResponseMessage> SubmitAsync(LoginPageConfig page, NostrEvent signed) =>
            PostFormAsync(page.Path, new() { ["state"] = page.State, ["event"] = signed.ToJson() });
    }

    internal sealed record LoginPageConfig(string Url, string Path, string State, string Challenge, int Kind, string? ConnectPath, bool Manual)
    {
        public NostrEvent Template(DateTimeOffset? at = null) =>
            Nip98.CreateTemplate(Url, "POST", at ?? DateTimeOffset.UtcNow, Challenge);
    }

    [GeneratedRegex("<script id=\"nostr-config\" type=\"application/json\">(.*?)</script>", RegexOptions.Singleline)]
    private static partial Regex ConfigRegex();
}
