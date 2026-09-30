// Demo 3: an API with NIP-98 HTTP Auth. No session and no cookie: every request carries
// "Authorization: Nostr <base64 signed event>" that names the exact URL and method (and body hash).
using System.Collections.Concurrent;
using System.Security.Claims;
using NostrAuth.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(NostrHttpAuthDefaults.AuthenticationScheme)
    .AddNostrHttpAuth(o => o.PublicOrigin = builder.Configuration["Nostr:PublicOrigin"]);
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

// Demo storage: notes per pubkey, in memory.
var notes = new ConcurrentDictionary<string, List<string>>();

app.MapGet("/api/public", () => new { message = "No auth needed here." });

var api = app.MapGroup("/api").RequireAuthorization();

api.MapGet("/me", (ClaimsPrincipal user) => new
{
    pubkey = user.FindFirstValue(NostrClaimTypes.PubKey),
    npub = user.FindFirstValue(NostrClaimTypes.Npub),
});

api.MapGet("/notes", (ClaimsPrincipal user) =>
    notes.GetValueOrDefault(user.FindFirstValue(NostrClaimTypes.PubKey)!) ?? []);

// A POST body must match the "payload" tag (SHA-256) of the signed event, so a captured
// header cannot be reused with other content.
api.MapPost("/notes", (ClaimsPrincipal user, NoteInput input) =>
{
    if (string.IsNullOrWhiteSpace(input.Text) || input.Text.Length > 280) return Results.BadRequest("Text must be 1 to 280 characters.");
    var list = notes.GetOrAdd(user.FindFirstValue(NostrClaimTypes.PubKey)!, _ => []);
    lock (list) list.Add(input.Text);
    return Results.Ok(list);
});

app.Run();

record NoteInput(string Text);
