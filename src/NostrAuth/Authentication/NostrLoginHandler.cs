using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NostrAuth.NostrConnect;
using NostrAuth.Relays;
using QRCoder;

namespace NostrAuth.Authentication;

/// <summary>
/// "Log in with Nostr" as a normal ASP.NET Core remote authentication scheme. It works like an
/// OAuth handler, but the "provider" is a page that this handler serves itself:
/// <list type="number">
/// <item>Challenge: make a single-use challenge, put it in the protected state, redirect to <c>GET CallbackPath</c>.</item>
/// <item><c>GET CallbackPath</c>: the login page. The user's signer signs a NIP-98 event with the challenge.</item>
/// <item><c>POST CallbackPath</c>: verify the event, then sign in to <see cref="RemoteAuthenticationOptions.SignInScheme"/>.</item>
/// </list>
/// Because it is a real scheme, ASP.NET Core Identity lists it as an external login with no extra code.
/// </summary>
public sealed class NostrLoginHandler(
    IOptionsMonitor<NostrLoginOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IChallengeStore challenges,
    NostrConnectService nostrConnect,
    ProfileFetcher profiles,
    TimeProvider time)
    : RemoteAuthenticationHandler<NostrLoginOptions>(options, logger, encoder)
{
    // Empty counts as "not set": an empty environment variable must not produce a relative URL.
    private string Origin => string.IsNullOrWhiteSpace(Options.PublicOrigin) ? $"{Request.Scheme}://{Request.Host}" : Options.PublicOrigin.TrimEnd('/');

    private const string ChallengeKey = ".nostr.challenge";
    private const string ConnectSegment = "/connect";

    private new NostrLoginEvents Events => (NostrLoginEvents)base.Events;

    /// <summary>The exact URL that the signed event must name in its <c>u</c> tag.</summary>
    private string CallbackUrl =>
        Origin + OriginalPathBase + Options.CallbackPath;

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        if (string.IsNullOrEmpty(properties.RedirectUri))
            properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;

        // The correlation cookie ties the state to this browser. Without it, an attacker could
        // make a victim's browser finish the attacker's login (login CSRF).
        GenerateCorrelationId(properties);
        properties.Items[ChallengeKey] = challenges.Issue(Options.ChallengeLifetime);

        var state = Options.StateDataFormat.Protect(properties);
        Response.Redirect($"{OriginalPathBase}{Options.CallbackPath}?state={Uri.EscapeDataString(state)}");
        return Task.CompletedTask;
    }

    public override async Task<bool> HandleRequestAsync()
    {
        var path = Request.Path;
        if (path == Options.CallbackPath && HttpMethods.IsGet(Request.Method))
        {
            await RenderLoginPageAsync();
            return true;
        }
        if (path == Options.CallbackPath.Add(ConnectSegment) && HttpMethods.IsPost(Request.Method))
        {
            await StartNostrConnectAsync();
            return true;
        }
        if (path.StartsWithSegments(Options.CallbackPath.Add(ConnectSegment), out var rest) && HttpMethods.IsGet(Request.Method))
        {
            await PollNostrConnectAsync(rest.Value!.TrimStart('/'));
            return true;
        }
        // POST CallbackPath: the base class calls HandleRemoteAuthenticateAsync.
        return await base.HandleRequestAsync();
    }

    private async Task RenderLoginPageAsync()
    {
        var (properties, challenge) = ReadState(Request.Query["state"]);
        if (properties is null || challenge is null)
        {
            Logger.LogInformation("Nostr login page opened with an invalid or expired state by {Ip}", Context.Connection.RemoteIpAddress);
            await LoginPage.WriteErrorAsync(Context, "The login link is invalid or expired.", null);
            return;
        }
        Logger.LogDebug("Nostr login page served to {Ip} for {Url}", Context.Connection.RemoteIpAddress, CallbackUrl);
        await LoginPage.WriteAsync(Context, Options.AppName, new
        {
            // url is the public URL for the u tag. path is where the form posts: relative, so the
            // POST goes to the address in the browser even when the server sees another scheme or host.
            url = CallbackUrl,
            path = $"{OriginalPathBase}{Options.CallbackPath}",
            state = Request.Query["state"].ToString(),
            challenge,
            kind = Nip98.Kind,
            connectPath = Options.NostrConnectRelays.Count > 0 ? $"{OriginalPathBase}{Options.CallbackPath}{ConnectSegment}" : null,
            manual = Options.AllowManualEvent,
        });
    }

    private async Task StartNostrConnectAsync()
    {
        var form = await Request.ReadFormAsync();
        var (properties, challenge) = ReadState(form["state"]);
        if (properties is null || challenge is null || Options.NostrConnectRelays.Count == 0)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var template = Nip98.CreateTemplate(CallbackUrl, HttpMethods.Post, time.GetUtcNow(), challenge);
        var origin = Origin;
        var session = await nostrConnect.StartAsync(template, [.. Options.NostrConnectRelays], Options.AppName, origin, Options.NostrConnectTimeout, Options.MaxNostrConnectSessions);
        if (session is null)
        {
            Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return;
        }
        Logger.LogInformation("Nostr Connect {Id}: QR code shown to {Ip}", session.Id, Context.Connection.RemoteIpAddress);

        using var qr = new QRCodeGenerator().CreateQrCode(session.ConnectUri, QRCodeGenerator.ECCLevel.L);
        await Response.WriteAsJsonAsync(new { id = session.Id, uri = session.ConnectUri, qrSvg = new SvgQRCode(qr).GetGraphic(4) });
    }

    private async Task PollNostrConnectAsync(string id)
    {
        // The id is 128 random bits. Knowing it gives only the signed event, and that event is
        // useless without this browser's correlation cookie and state.
        if (nostrConnect.Get(id) is not { } s)
        {
            Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        Response.Headers.CacheControl = "no-store";
        var now = time.GetUtcNow();
        await Response.WriteAsJsonAsync(new
        {
            status = s.Status.ToString(),
            authUrl = s.AuthUrl,
            @event = s.SignedEventJson,
            error = s.Error,
            // "Connection details" on the page: the true state, so a stuck login explains itself.
            signer = s.Signer is { } signer ? new { pubKey = signer.PubKey, via = signer.Via, clockOffset = signer.ClockOffset } : null,
            userPubKey = s.UserPubKey,
            request = s.Request is { } r ? new { method = r.Method, copies = r.Copies, sentAgo = (int)(now - r.LastSent).TotalSeconds } : null,
            relays = s.RelayUrls.Select(url => s.Relays.TryGetValue(url, out var state)
                ? new { url, state = state.State, detail = state.Detail }
                : new { url, state = "unknown", detail = (string?)null }),
            timeline = s.Timeline.Select(e => new { at = e.At.ToUnixTimeMilliseconds(), text = e.Text }),
        });
    }

    private (AuthenticationProperties? Properties, string? Challenge) ReadState(string? state)
    {
        var properties = string.IsNullOrEmpty(state) ? null : Options.StateDataFormat.Unprotect(state);
        return (properties, properties?.Items.TryGetValue(ChallengeKey, out var c) == true ? c : null);
    }

    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        if (!HttpMethods.IsPost(Request.Method) || !Request.HasFormContentType)
            return HandleRequestResult.Fail("Expected a form POST.");

        var form = await Request.ReadFormAsync();
        var (properties, challenge) = ReadState(form["state"]);
        if (properties is null || challenge is null) return Reject("The login state is invalid or expired.");
        if (!ValidateCorrelationId(properties)) return Reject("Correlation failed. Start the login again in the same browser.", properties);

        var proof = NostrEvent.TryParse(form["event"]);
        if (proof is null) return Reject("The signed event is missing or malformed.", properties);

        var error = Nip98.Validate(proof, CallbackUrl, HttpMethods.Post, time.GetUtcNow(), Options.MaxEventAge, Options.MaxFutureSkew);
        // The challenge comes from our protected state, never from the browser, so the user cannot pick it.
        error ??= proof.GetTag("challenge") != challenge ? "Challenge does not match." : null;
        // Consume last: all cheap checks pass first, then the challenge is burnt exactly once.
        error ??= challenges.TryConsume(challenge) ? null : "Challenge is expired or already used.";
        if (error is not null) return Reject(error, properties, proof);

        Logger.LogInformation("Nostr login OK for {PubKey} with event {EventId} (created_at {CreatedAt}, u {Url})", proof.PubKey, proof.Id, proof.CreatedAt, CallbackUrl);
        var principal = await CreatePrincipalAsync(proof.PubKey);
        var context = new NostrCreatingTicketContext(Context, Scheme, Options, principal, properties, proof);
        await Events.CreatingTicket(context);
        return HandleRequestResult.Success(new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name));
    }

    private HandleRequestResult Reject(string error, AuthenticationProperties? properties = null, NostrEvent? proof = null)
    {
        // Every refused login leaves a line: "it does not log me in" reports come without details.
        Logger.LogInformation("Nostr login rejected: {Error} (pubkey {PubKey}, event created_at {CreatedAt}, u tag '{UTag}', expected u {Url}, client {Ip})",
            error, proof?.PubKey ?? "none", proof?.CreatedAt, proof?.GetTag("u") ?? "none", CallbackUrl, Context.Connection.RemoteIpAddress);
        return HandleRequestResult.Fail(error, properties);
    }

    private async Task<ClaimsPrincipal> CreatePrincipalAsync(string pubKey)
    {
        var npub = Nip19.ToNpub(pubKey);
        var profile = await profiles.FetchAsync(pubKey, [.. Options.ProfileRelays], Options.ProfileTimeout, Context.RequestAborted);

        var identity = new ClaimsIdentity(Scheme.Name);
        // The hex key is the stable identity. Names and pictures are display data that the user can change.
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, pubKey, ClaimValueTypes.String, ClaimsIssuer));
        identity.AddClaim(new Claim(NostrClaimTypes.PubKey, pubKey, ClaimValueTypes.String, ClaimsIssuer));
        identity.AddClaim(new Claim(NostrClaimTypes.Npub, npub, ClaimValueTypes.String, ClaimsIssuer));
        identity.AddClaim(new Claim(ClaimTypes.Name, profile?.Name ?? ShortNpub(npub), ClaimValueTypes.String, ClaimsIssuer));
        if (profile?.Name is { } name) identity.AddClaim(new Claim(NostrClaimTypes.Name, name, ClaimValueTypes.String, ClaimsIssuer));
        if (profile?.Picture is { } picture) identity.AddClaim(new Claim(NostrClaimTypes.Picture, picture, ClaimValueTypes.String, ClaimsIssuer));
        if (profile is { Nip05Verified: true, Nip05: { } nip05 }) identity.AddClaim(new Claim(NostrClaimTypes.Nip05, nip05, ClaimValueTypes.String, ClaimsIssuer));
        return new ClaimsPrincipal(identity);
    }

    internal static string ShortNpub(string npub) => $"{npub[..10]}…{npub[^6..]}";
}
