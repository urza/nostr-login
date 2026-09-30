// Demo 4b: an ordinary ASP.NET Core app. It has no Nostr code and no NostrAuth reference.
// It trusts the Nostr ID provider (demo 4a) through standard OpenID Connect.
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(o =>
    {
        o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    // Browsers share cookies across ports, and all demos run on localhost. Distinct names keep them apart.
    .AddCookie(o => o.Cookie.Name = "OidcClientDemo")
    .AddOpenIdConnect(o =>
    {
        o.Authority = builder.Configuration["Oidc:Authority"] ?? "http://localhost:5104";
        o.ClientId = "demo-client";
        o.ClientSecret = "demo-secret-change-me";
        o.ResponseType = "code";
        o.UsePkce = true;
        o.Scope.Add("profile");
        o.GetClaimsFromUserInfoEndpoint = true;
        o.SaveTokens = true;
        // Keep the short OIDC claim names ("sub", "name") instead of the long WS-* URIs.
        o.MapInboundClaims = false;
        o.TokenValidationParameters.NameClaimType = "name";
        // The demo provider runs on plain http. Never do this in production.
        o.RequireHttpsMetadata = false;
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext ctx) => Html(ctx.User.Identity?.IsAuthenticated == true
    ? $"""<p>Hello <strong>{Enc(ctx.User.Identity.Name)}</strong>. <a href="/account">Account</a> · <a href="/logout">Log out</a></p>"""
    : """<p><a class="button" href="/account">Log in</a> <span class="muted">(through the Nostr ID provider)</span></p>"""));

app.MapGet("/account", (HttpContext ctx) =>
{
    var picture = ctx.User.FindFirst("picture")?.Value;
    var rows = string.Concat(ctx.User.Claims.Select(c => $"<tr><td>{Enc(c.Type)}</td><td>{Enc(c.Value)}</td></tr>"));
    return Html($"""
        {(picture is null ? "" : $"""<img src="{Enc(picture)}" alt="" width="64" height="64" style="border-radius:50%;object-fit:cover" referrerpolicy="no-referrer">""")}
        <h2>{Enc(ctx.User.Identity!.Name)}</h2>
        <p>Your user id in this app is the OIDC <code>sub</code> claim: <code>{Enc(ctx.User.FindFirst("sub")?.Value)}</code>.
        It is your Nostr public key, but this app does not need to know that.</p>
        <table><tr><th>Claim</th><th>Value</th></tr>{rows}</table>
        <p><a href="/logout">Log out</a></p>
        """);
}).RequireAuthorization();

// Signs out here and at the provider (RP-initiated logout), then comes back to "/".
app.MapGet("/logout", () => Results.SignOut(new AuthenticationProperties { RedirectUri = "/" },
    [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));

app.Run();

static string Enc(string? s) => HtmlEncoder.Default.Encode(s ?? "");

static IResult Html(string body) => Results.Content($"""
    <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>OIDC client demo</title>
    <style>
      body {"{"} font: 16px/1.55 system-ui, sans-serif; max-width: 46rem; margin: 2rem auto; padding: 0 1rem; {"}"}
      table {"{"} border-collapse: collapse; width: 100%; font-size: .9rem; {"}"}
      td, th {"{"} text-align: left; border-bottom: 1px solid #ddd; padding: .35rem .5rem; word-break: break-all; {"}"}
      code {"{"} background: #f0eef5; padding: 0 .25rem; border-radius: 4px; word-break: break-all; {"}"}
      .button {"{"} background: #1f6feb; color: #fff; padding: .5rem 1rem; border-radius: 8px; text-decoration: none; {"}"}
      .muted {"{"} color: #666; {"}"}
    </style></head>
    <body><h1>OIDC client demo</h1><p class="muted">A normal app. It knows OpenID Connect, not Nostr.</p>{body}</body></html>
    """, "text/html; charset=utf-8");
