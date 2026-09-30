// Nostr Guestbook: log in with a Nostr key, leave one public message.
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using NostrAuth.Authentication;
using NostrGuestbook.Data;
using NostrGuestbook.Profiles;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

// Database and Data Protection keys live together in one folder: mount it as a volume and
// messages and logins survive a container restart. Without the keys, every restart would
// log all users out, because the cookies could not be decrypted any more.
// Default folder name differs from the "Data" source folder in more than case: on a
// case-insensitive disk (Windows, macOS) "data" and "Data" are the same folder.
var dataDir = Path.GetFullPath(config["Guestbook:DataDirectory"] ?? Path.Combine(builder.Environment.ContentRootPath, "guestbook-data"));
Directory.CreateDirectory(dataDir);
builder.Services.AddDbContext<GuestbookDb>(o => o.UseSqlite($"Data Source={Path.Combine(dataDir, "guestbook.db")}"));
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDir, "keys")))
    .SetApplicationName("NostrGuestbook");

// A relay list from configuration replaces the default list. Bind would append to it instead.
string[]? Relays(string key) => config.GetSection(key).Get<string[]>() is { Length: > 0 } r ? r : null;
builder.Services.Configure<ProfileRelayOptions>(o => o.Relays = Relays("Nostr:ProfileRelays") ?? [.. new NostrLoginOptions().ProfileRelays]);
builder.Services.AddSingleton<ProfileRefresher>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ProfileRefresher>());

builder.Services.AddAuthentication(o =>
    {
        o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.DefaultChallengeScheme = NostrLoginDefaults.AuthenticationScheme;
    })
    .AddCookie(o =>
    {
        o.Cookie.Name = "NostrGuestbook";
        o.ExpireTimeSpan = TimeSpan.FromDays(30);
        o.SlidingExpiration = true;
    })
    .AddNostr(o =>
    {
        o.AppName = "Nostr Guestbook";
        o.PublicOrigin = config["Nostr:PublicOrigin"];
        if (Relays("Nostr:NostrConnectRelays") is { } connectRelays) o.NostrConnectRelays = connectRelays;
        // No profile lookup during login: the user gets in at once, and ProfileRefresher
        // loads name and picture in the background while the page shows its progress.
        o.ProfileRelays = [];
        o.Events.OnTicketReceived = async context =>
        {
            var pubKey = context.Principal!.FindFirstValue(NostrClaimTypes.PubKey)!;
            var services = context.HttpContext.RequestServices;
            await services.GetRequiredService<ProfileRefresher>().EnqueueAsync(pubKey, services.GetRequiredService<GuestbookDb>());
        };
    });
builder.Services.AddAuthorization();
builder.Services.AddRazorPages();

// Keys cost nothing, so anyone can make many accounts. A per-IP limit on all POSTs (login,
// Nostr Connect, message saves) keeps floods small. Behind a reverse proxy, set
// ASPNETCORE_FORWARDEDHEADERS_ENABLED=true, or all users share the proxy's IP and one limit.
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
        HttpMethods.IsPost(ctx.Request.Method)
            ? RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions { PermitLimit = 30, Window = TimeSpan.FromMinutes(1) })
            : RateLimitPartition.GetNoLimiter("read"));
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<GuestbookDb>();
    db.Database.Migrate();
    // Lookups do not survive a restart. Without this, a profile stuck in "Fetching" would
    // show a spinner until the user logs in again.
    db.Profiles.Where(p => p.Status == ProfileStatus.Queued || p.Status == ProfileStatus.Fetching)
        .ExecuteUpdate(u => u.SetProperty(p => p.Status, ProfileStatus.NotFound));
}

if (!app.Environment.IsDevelopment()) app.UseExceptionHandler("/Error");
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapStaticAssets();
app.MapRazorPages().WithStaticAssets();

app.MapGet("/login", () => Results.Challenge(new AuthenticationProperties { RedirectUri = "/#me" }, [NostrLoginDefaults.AuthenticationScheme]));

// Polled by the "fetching your profile" panel.
app.MapGet("/api/me/profile", async (ClaimsPrincipal user, GuestbookDb db, ProfileRefresher refresher) =>
{
    var pubKey = user.FindFirstValue(NostrClaimTypes.PubKey)!;
    var profile = await db.Profiles.AsNoTracking().FirstOrDefaultAsync(p => p.PubKey == pubKey);
    var progress = refresher.GetProgress(pubKey);
    return Results.Ok(new
    {
        status = profile?.Status.ToString() ?? nameof(ProfileStatus.NotFound),
        done = profile?.Status is not (ProfileStatus.Queued or ProfileStatus.Fetching),
        name = profile?.Name,
        picture = profile?.Picture,
        nip05 = profile?.Nip05Verified == true ? profile.Nip05 : null,
        steps = progress?.Steps.Select(s => new { source = s.Source, outcome = s.Outcome.ToString(), detail = s.Detail }) ?? [],
    });
}).RequireAuthorization();

app.MapGet("/healthz", () => Results.Text("ok"));

app.Run();
