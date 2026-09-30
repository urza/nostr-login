using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using NostrAuth.Authentication;
using NostrAuth.NostrConnect;
using NostrAuth.Relays;

// Same namespace as AddCookie and AddOpenIdConnect, so apps need no extra using.
namespace Microsoft.Extensions.DependencyInjection;

public static class NostrAuthenticationExtensions
{
    /// <summary>Adds the "Log in with Nostr" scheme (login page, NIP-07, NIP-46 and manual signing).</summary>
    public static AuthenticationBuilder AddNostr(this AuthenticationBuilder builder, Action<NostrLoginOptions>? configure = null) =>
        builder.AddNostr(NostrLoginDefaults.AuthenticationScheme, NostrLoginDefaults.DisplayName, configure);

    public static AuthenticationBuilder AddNostr(this AuthenticationBuilder builder, string scheme, string displayName, Action<NostrLoginOptions>? configure)
    {
        var services = builder.Services;
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IChallengeStore, InMemoryChallengeStore>();
        services.TryAddSingleton<NostrConnectService>();
        services.TryAddSingleton<ProfileFetcher>();
        services.AddHttpClient(ProfileFetcher.Nip05HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(5))
            .ConfigurePrimaryHttpMessageHandler(PublicOnlyHttpHandler.Create);
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<NostrLoginOptions>, NostrLoginPostConfigure>());
        return builder.AddRemoteScheme<NostrLoginOptions, NostrLoginHandler>(scheme, displayName, configure);
    }

    /// <summary>Adds NIP-98 HTTP Auth (<c>Authorization: Nostr ...</c>) for APIs.</summary>
    public static AuthenticationBuilder AddNostrHttpAuth(this AuthenticationBuilder builder, Action<NostrHttpAuthOptions>? configure = null)
    {
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.AddMemoryCache();
        return builder.AddScheme<NostrHttpAuthOptions, NostrHttpAuthHandler>(NostrHttpAuthDefaults.AuthenticationScheme, "Nostr HTTP Auth", configure);
    }

    private sealed class NostrLoginPostConfigure(IDataProtectionProvider dataProtection) : IPostConfigureOptions<NostrLoginOptions>
    {
        public void PostConfigure(string? name, NostrLoginOptions options)
        {
            options.DataProtectionProvider ??= dataProtection;
            options.StateDataFormat ??= new PropertiesDataFormat(
                options.DataProtectionProvider.CreateProtector(typeof(NostrLoginHandler).FullName!, name ?? "", "v1"));
        }
    }
}
