using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NostrAuth.Authentication;

public static class NostrHttpAuthDefaults
{
    public const string AuthenticationScheme = "NostrHttp";
}

public class NostrHttpAuthOptions : AuthenticationSchemeOptions
{
    /// <summary>NIP-98 suggests 60 seconds.</summary>
    public TimeSpan MaxEventAge { get; set; } = TimeSpan.FromSeconds(60);
    public TimeSpan MaxFutureSkew { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>See <see cref="NostrLoginOptions.PublicOrigin"/>.</summary>
    public string? PublicOrigin { get; set; }

    /// <summary>Reject a request with a body but no matching <c>payload</c> tag. NIP-98 only says SHOULD.</summary>
    public bool RequirePayloadHash { get; set; } = true;

    /// <summary>Largest body that the handler reads to check the payload hash.</summary>
    public long MaxBodyBytes { get; set; } = 1024 * 1024;
}

/// <summary>
/// NIP-98: each request carries <c>Authorization: Nostr base64(signed kind-27235 event)</c>.
/// For API clients that hold a signer. No session, no cookie.
/// </summary>
public sealed class NostrHttpAuthHandler(
    IOptionsMonitor<NostrHttpAuthOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IMemoryCache seenEvents,
    TimeProvider time)
    : AuthenticationHandler<NostrHttpAuthOptions>(options, logger, encoder)
{
    // Empty counts as "not set": an empty environment variable must not produce a relative URL.
    private string Origin => string.IsNullOrWhiteSpace(Options.PublicOrigin) ? $"{Request.Scheme}://{Request.Host}" : Options.PublicOrigin.TrimEnd('/');

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? header = Request.Headers.Authorization;
        if (header is null || !header.StartsWith(Nip98.Scheme + " ", StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.NoResult();

        NostrEvent? evt;
        try
        {
            evt = NostrEvent.TryParse(Encoding.UTF8.GetString(Convert.FromBase64String(header[(Nip98.Scheme.Length + 1)..].Trim())));
        }
        catch (FormatException)
        {
            evt = null;
        }
        if (evt is null) return AuthenticateResult.Fail("Authorization header is not a base64 Nostr event.");

        var body = await ReadBodyAsync();
        if (body is null) return AuthenticateResult.Fail("Request body is too large.");

        var url = Origin + Request.PathBase + Request.Path + Request.QueryString;
        var error = Nip98.Validate(evt, url, Request.Method, time.GetUtcNow(), Options.MaxEventAge, Options.MaxFutureSkew, body);
        if (error is null && Options.RequirePayloadHash && body.Length > 0 && evt.GetTag("payload") is null)
            error = "Payload tag is required for a request with a body.";
        if (error is not null) return AuthenticateResult.Fail(error);

        // NIP-98 alone allows replay inside the time window. Remember each signature for that
        // window and reject a second use. Keyed by sig, not id: two honest requests to the same
        // URL in the same second have the same id, but BIP-340 aux randomness gives them different
        // signatures. A replayed header is byte-identical. A multi-node app needs a shared store here.
        var key = "nip98:" + evt.Sig;
        if (seenEvents.TryGetValue(key, out _)) return AuthenticateResult.Fail("Event was already used.");
        seenEvents.Set(key, true, Options.MaxEventAge + Options.MaxFutureSkew);

        var identity = new ClaimsIdentity(Scheme.Name);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, evt.PubKey));
        identity.AddClaim(new Claim(NostrClaimTypes.PubKey, evt.PubKey));
        identity.AddClaim(new Claim(NostrClaimTypes.Npub, Nip19.ToNpub(evt.PubKey)));
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }

    private async Task<byte[]?> ReadBodyAsync()
    {
        // Always read, never decide from headers: an HTTP/2 request can carry a body with neither
        // Content-Length nor Transfer-Encoding, and skipping it would skip the payload check.
        if (Request.ContentLength > Options.MaxBodyBytes) return null;

        // The endpoint reads the body again after us, so rewind it.
        Request.EnableBuffering();
        using var ms = new MemoryStream();
        var buffer = new byte[16 * 1024];
        int read;
        while ((read = await Request.Body.ReadAsync(buffer, Context.RequestAborted)) > 0)
        {
            ms.Write(buffer, 0, read);
            if (ms.Length > Options.MaxBodyBytes) return null;
        }
        Request.Body.Position = 0;
        return ms.ToArray();
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = Nip98.Scheme;
        return Task.CompletedTask;
    }
}
