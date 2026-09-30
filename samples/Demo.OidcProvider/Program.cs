// Demo 4a: a Nostr identity provider. Users log in with Nostr here, once. Other apps use plain
// OpenID Connect and never see Nostr code. The OIDC "sub" claim is the hex pubkey.
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using NostrAuth.Authentication;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
var clientBaseUrl = builder.Configuration["DemoClient:BaseUrl"] ?? "http://localhost:5105";

// OpenIddict stores clients, codes and tokens in EF Core. In memory is enough for a demo.
builder.Services.AddDbContext<DbContext>(o =>
{
    o.UseInMemoryDatabase("oidc");
    o.UseOpenIddict();
});

builder.Services.AddAuthentication(o =>
    {
        o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.DefaultChallengeScheme = NostrLoginDefaults.AuthenticationScheme;
    })
    // Browsers share cookies across ports, and all demos run on localhost. Distinct names keep them apart.
    .AddCookie(o => o.Cookie.Name = "NostrIdProvider")
    .AddNostr(o =>
    {
        // The user signs a login for this provider's URL, not for the client app.
        o.AppName = "Nostr ID (demo provider)";
        o.PublicOrigin = builder.Configuration["Nostr:PublicOrigin"];
        // Replace, not bind: the configuration binder appends to a list that already has default items.
        if (builder.Configuration.GetSection("Nostr:NostrConnectRelays").Get<string[]>() is { Length: > 0 } relays)
            o.NostrConnectRelays = relays;
    });

builder.Services.AddOpenIddict()
    .AddCore(o => o.UseEntityFrameworkCore().UseDbContext<DbContext>())
    .AddServer(o =>
    {
        o.SetAuthorizationEndpointUris("connect/authorize")
            .SetTokenEndpointUris("connect/token")
            .SetUserInfoEndpointUris("connect/userinfo")
            .SetEndSessionEndpointUris("connect/logout");
        o.AllowAuthorizationCodeFlow().RequireProofKeyForCodeExchange();
        o.RegisterScopes(Scopes.OpenId, Scopes.Profile);
        // Demo keys, new on each start. A real provider loads certificates from a key store.
        o.AddEphemeralEncryptionKey().AddEphemeralSigningKey();
        o.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableUserInfoEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough()
            // The demo runs on plain http. Never disable this in production.
            .DisableTransportSecurityRequirement();
    });

var app = builder.Build();

await RegisterDemoClientAsync(app.Services, clientBaseUrl);

app.UseAuthentication();

app.MapGet("/", (HttpContext ctx) => Html($"""
    <h1>Nostr ID (demo provider)</h1>
    <p>An OpenID Connect provider where the user proves a Nostr key. The <code>sub</code> claim is the hex pubkey.</p>
    <p>Discovery document: <a href="/.well-known/openid-configuration">/.well-known/openid-configuration</a></p>
    <p>Registered client: <a href="{Enc(clientBaseUrl)}">{Enc(clientBaseUrl)}</a></p>
    <p>{(ctx.User.Identity?.IsAuthenticated == true ? $"You have a provider session as <strong>{Enc(ctx.User.Identity.Name)}</strong>." : "You have no provider session.")}</p>
    """));

// Authorization endpoint. OpenIddict has already validated the client, redirect URI and PKCE.
// This code only answers "who is the user?".
app.MapGet("connect/authorize", async (HttpContext ctx) =>
{
    var request = ctx.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("Not an OpenID Connect request.");

    var session = await ctx.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    if (!session.Succeeded || request.HasPromptValue(PromptValues.Login))
    {
        if (request.HasPromptValue(PromptValues.None))
            return Forbid(Errors.LoginRequired, "The user is not logged in.");

        // No provider session: run the Nostr login, then come back to this same URL.
        // Drop prompt=login from the return URL, or the user would loop back to the login page.
        var parameters = ctx.Request.Query.Where(p => p.Key != Parameters.Prompt).ToList();
        return Results.Challenge(new AuthenticationProperties { RedirectUri = ctx.Request.PathBase + ctx.Request.Path + QueryString.Create(parameters) },
            [NostrLoginDefaults.AuthenticationScheme]);
    }

    var user = session.Principal!;
    var identity = new ClaimsIdentity(
        authenticationType: "Nostr",
        nameType: Claims.Name, roleType: Claims.Role);
    identity.SetClaim(Claims.Subject, user.FindFirstValue(NostrClaimTypes.PubKey))
        .SetClaim(Claims.Name, user.FindFirstValue(ClaimTypes.Name))
        .SetClaim(Claims.PreferredUsername, user.FindFirstValue(NostrClaimTypes.Npub))
        .SetClaim(Claims.Picture, user.FindFirstValue(NostrClaimTypes.Picture))
        .SetClaim("nip05", user.FindFirstValue(NostrClaimTypes.Nip05))
        .SetClaim("npub", user.FindFirstValue(NostrClaimTypes.Npub));
    identity.SetScopes(request.GetScopes());
    identity.SetDestinations(claim => claim.Type switch
    {
        // Profile data goes into the id_token only when the client asked for the profile scope.
        Claims.Name or Claims.PreferredUsername or Claims.Picture or "nip05" or "npub" when identity.HasScope(Scopes.Profile)
            => [Destinations.AccessToken, Destinations.IdentityToken],
        _ => [Destinations.AccessToken],
    });

    // Consent: the demo client is registered with implicit consent, so no consent page.
    return Results.SignIn(new ClaimsPrincipal(identity), authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
});

app.MapGet("connect/userinfo", async (HttpContext ctx) =>
{
    var result = await ctx.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    if (!result.Succeeded) return Results.Challenge(authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    var p = result.Principal!;
    var claims = new Dictionary<string, object?> { [Claims.Subject] = p.GetClaim(Claims.Subject) };
    if (p.HasScope(Scopes.Profile))
    {
        foreach (var type in new[] { Claims.Name, Claims.PreferredUsername, Claims.Picture, "nip05", "npub" })
            if (p.GetClaim(type) is { } value) claims[type] = value;
    }
    return Results.Ok(claims);
});

app.MapGet("connect/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    // OpenIddict validates post_logout_redirect_uri and redirects there.
    return Results.SignOut(new AuthenticationProperties { RedirectUri = "/" }, [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
});

app.Run();

static IResult Forbid(string error, string description) => Results.Forbid(
    new AuthenticationProperties(new Dictionary<string, string?>
    {
        [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
    }),
    [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);

static string Enc(string? s) => HtmlEncoder.Default.Encode(s ?? "");

static IResult Html(string body) => Results.Content($"""
    <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Nostr ID (demo provider)</title>
    <style>body{"{"}font:16px/1.55 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem{"}"}code{"{"}background:#f0eef5;padding:0 .25rem;border-radius:4px{"}"}</style>
    </head><body>{body}</body></html>
    """, "text/html; charset=utf-8");

static async Task RegisterDemoClientAsync(IServiceProvider services, string clientBaseUrl)
{
    using var scope = services.CreateScope();
    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    if (await manager.FindByClientIdAsync("demo-client") is not null) return;

    await manager.CreateAsync(new OpenIddictApplicationDescriptor
    {
        ClientId = "demo-client",
        ClientSecret = "demo-secret-change-me",
        ClientType = ClientTypes.Confidential,
        ConsentType = ConsentTypes.Implicit,
        DisplayName = "OIDC client demo",
        RedirectUris = { new Uri($"{clientBaseUrl}/signin-oidc") },
        PostLogoutRedirectUris = { new Uri($"{clientBaseUrl}/signout-callback-oidc") },
        Permissions =
        {
            Permissions.Endpoints.Authorization,
            Permissions.Endpoints.Token,
            Permissions.Endpoints.EndSession,
            Permissions.GrantTypes.AuthorizationCode,
            Permissions.ResponseTypes.Code,
            Permissions.Scopes.Profile,
        },
        Requirements = { Requirements.Features.ProofKeyForCodeExchange },
    });
}
