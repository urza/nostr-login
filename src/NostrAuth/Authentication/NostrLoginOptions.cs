using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace NostrAuth.Authentication;

public static class NostrLoginDefaults
{
    public const string AuthenticationScheme = "Nostr";
    public const string DisplayName = "Nostr";
}

public static class NostrClaimTypes
{
    /// <summary>64-char lowercase hex public key. Also the <c>NameIdentifier</c> claim.</summary>
    public const string PubKey = "nostr:pubkey";
    public const string Npub = "nostr:npub";
    /// <summary>Name from the kind-0 profile. Absent when the profile has no name (then <c>ClaimTypes.Name</c> is a short npub).</summary>
    public const string Name = "nostr:name";
    public const string Picture = "nostr:picture";
    /// <summary>Only present when the NIP-05 identifier resolved to this pubkey at login time.</summary>
    public const string Nip05 = "nostr:nip05";
}

public class NostrLoginOptions : RemoteAuthenticationOptions
{
    public NostrLoginOptions()
    {
        CallbackPath = "/signin-nostr";
        // Every request of this flow comes from our own page, never from a third-party site.
        // Lax works on plain http during development too. SameSite=None would need https.
        CorrelationCookie.SameSite = SameSiteMode.Lax;
        CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        Events = new NostrLoginEvents();
    }

    /// <summary>Title of the built-in login page, and the app name that the signer app shows.</summary>
    public string AppName { get; set; } = "ASP.NET Core app";

    /// <summary>How long the login page stays valid.</summary>
    public TimeSpan ChallengeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    public TimeSpan MaxEventAge { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan MaxFutureSkew { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Public origin, for example <c>https://app.example.com</c>. The signed event must contain the exact
    /// login URL. Behind a reverse proxy the request host can differ from the public one, so set this
    /// (or use ForwardedHeaders middleware). Null: use the request scheme and host.
    /// </summary>
    public string? PublicOrigin { get; set; }

    /// <summary>
    /// Relays for NIP-46 (Nostr Connect). Empty list: the QR code option is off. Several relays, because
    /// public relays go down. These are the relays that signer apps and NIP-46 clients use themselves,
    /// not general-purpose relays: relay.primal.net first, because Primal answers only on the first
    /// relay of the URI; relay.nsec.app is the nsec.app signer's own relay; the others are known to
    /// carry kind 24133 reliably. All except relay.nsec.app (not reachable from the test network)
    /// passed a kind-24133 round trip from a fresh key on 2026-10-01. Not in the list: relay.damus.io
    /// accepted kind-24133 events but never delivered them.
    /// </summary>
    public IList<string> NostrConnectRelays { get; set; } =
        ["wss://relay.primal.net", "wss://relay.nsec.app", "wss://theforest.nostr1.com", "wss://nostr.oxtr.dev", "wss://nostr.cypherpunk.today"];

    public TimeSpan NostrConnectTimeout { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Upper limit of NIP-46 sessions that wait for a signer at the same time, per app instance.</summary>
    public int MaxNostrConnectSessions { get; set; } = 100;

    /// <summary>
    /// Relays to read the kind-0 profile from. Empty list: no profile lookup. purplepag.es collects
    /// profiles from many relays: in a test, a Primal user's profile was there and on none of the others.
    /// </summary>
    public IList<string> ProfileRelays { get; set; } = ["wss://purplepag.es", "wss://relay.primal.net", "wss://relay.damus.io", "wss://nos.lol"];

    public TimeSpan ProfileTimeout { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>Shows the "paste a signed event" box. Useful for tests and CLI signers such as <c>nak</c>.</summary>
    public bool AllowManualEvent { get; set; } = true;

    public new NostrLoginEvents Events
    {
        get => (NostrLoginEvents)base.Events;
        set => base.Events = value;
    }

    public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = default!;

    public override void Validate()
    {
        base.Validate();
        // "app.example.com" without a scheme would still pass the login: the u tag and its check use
        // the same string. But the signer would show a strange address, and the login page could not
        // compare it with the browser address. Fail at the first request with a clear message instead.
        if (!string.IsNullOrWhiteSpace(PublicOrigin)
            && !(Uri.TryCreate(PublicOrigin, UriKind.Absolute, out var origin) && origin.Scheme is "http" or "https"))
            throw new InvalidOperationException($"{nameof(PublicOrigin)} must be an absolute http(s) URL such as https://app.example.com, not '{PublicOrigin}'.");
    }
}

public class NostrLoginEvents : RemoteAuthenticationEvents
{
    public NostrLoginEvents()
    {
        // The default remote failure behavior throws, which gives the user a 500 page for a
        // simple thing like an expired challenge. Show the reason and a way to start again instead.
        OnRemoteFailure = context =>
        {
            context.HandleResponse();
            return LoginPage.WriteErrorAsync(context.HttpContext, context.Failure?.Message ?? "Login failed.", context.Properties?.RedirectUri);
        };
    }

    /// <summary>Runs after the proof is valid and before the ticket is issued. Add or change claims here.</summary>
    public Func<NostrCreatingTicketContext, Task> OnCreatingTicket { get; set; } = _ => Task.CompletedTask;

    public virtual Task CreatingTicket(NostrCreatingTicketContext context) => OnCreatingTicket(context);
}

public class NostrCreatingTicketContext : PrincipalContext<NostrLoginOptions>
{
    public NostrCreatingTicketContext(
        HttpContext context, AuthenticationScheme scheme, NostrLoginOptions options,
        System.Security.Claims.ClaimsPrincipal principal, AuthenticationProperties properties, NostrEvent proof)
        : base(context, scheme, options, properties)
    {
        Principal = principal;
        Proof = proof;
    }

    /// <summary>The verified login event.</summary>
    public NostrEvent Proof { get; }
}
