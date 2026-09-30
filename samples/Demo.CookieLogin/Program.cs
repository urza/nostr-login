// Demo 1: the smallest useful "Log in with Nostr".
// The app has no user database. The Nostr pubkey is the user id, kept in a normal auth cookie.
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using NostrAuth.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddAuthentication(o =>
    {
        o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        // [Authorize] pages send anonymous users straight to the Nostr login page.
        o.DefaultChallengeScheme = NostrLoginDefaults.AuthenticationScheme;
    })
    .AddCookie(o =>
    {
        // Browsers share cookies across ports, and all demos run on localhost. Distinct names keep them apart.
        o.Cookie.Name = "CookieLoginDemo";
        o.ExpireTimeSpan = TimeSpan.FromHours(8);
    })
    .AddNostr(o =>
    {
        o.AppName = "Cookie login demo";
        // Set Nostr__PublicOrigin when the app runs behind a proxy or port forward with another host name.
        o.PublicOrigin = builder.Configuration["Nostr:PublicOrigin"];
        // Replace, not bind: the configuration binder appends to a list that already has default items.
        if (builder.Configuration.GetSection("Nostr:NostrConnectRelays").Get<string[]>() is { Length: > 0 } relays)
            o.NostrConnectRelays = relays;
    });

var app = builder.Build();

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();

app.MapGet("/login", (string? returnUrl) =>
    // Only local return URLs, or /login becomes an open redirect.
    Results.Challenge(
        new AuthenticationProperties { RedirectUri = returnUrl is ['/', not '/' and not '\\', ..] ? returnUrl : "/account" },
        [NostrLoginDefaults.AuthenticationScheme]));

app.Run();
