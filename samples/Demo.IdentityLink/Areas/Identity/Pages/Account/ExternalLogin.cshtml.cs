using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NostrAuth.Authentication;

namespace Demo.IdentityLink.Areas.Identity.Pages.Account;

/// <summary>
/// Replaces the Identity UI page of the same path. The built-in page requires an email for a new
/// external account. A Nostr login has no email, so here the email is optional and the user name is the npub.
/// </summary>
[AllowAnonymous]
public class ExternalLoginModel(
    SignInManager<IdentityUser> signInManager,
    UserManager<IdentityUser> userManager,
    ILogger<ExternalLoginModel> logger) : PageModel
{
    [BindProperty] public InputModel Input { get; set; } = new();

    public string ProviderDisplayName { get; private set; } = "";
    public string? ReturnUrl { get; private set; }
    public string? DisplayName { get; private set; }
    public string? Npub { get; private set; }
    public string? Picture { get; private set; }

    [TempData] public string? ErrorMessage { get; set; }

    public class InputModel
    {
        [EmailAddress]
        [Display(Name = "Email (optional)")]
        public string? Email { get; set; }
    }

    public IActionResult OnGet() => RedirectToPage("./Login");

    public IActionResult OnPost(string provider, string? returnUrl = null)
    {
        var redirectUrl = Url.Page("./ExternalLogin", pageHandler: "Callback", values: new { returnUrl });
        var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return new ChallengeResult(provider, properties);
    }

    public async Task<IActionResult> OnGetCallbackAsync(string? returnUrl = null, string? remoteError = null)
    {
        returnUrl ??= Url.Content("~/");
        if (remoteError is not null)
        {
            ErrorMessage = $"Error from external provider: {remoteError}";
            return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
        }

        var info = await signInManager.GetExternalLoginInfoAsync();
        if (info is null)
        {
            ErrorMessage = "Error loading external login information.";
            return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
        }

        // A key that is already linked signs in to its account. The key signature is strong
        // proof on its own, so the demo skips 2FA like Identity UI does for all external logins.
        var result = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
        if (result.Succeeded)
        {
            if (await userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey) is { } user && await SyncProfileAsync(user, info))
                await signInManager.RefreshSignInAsync(user);
            logger.LogInformation("{Name} logged in with {Provider}.", info.Principal.Identity?.Name, info.LoginProvider);
            return LocalRedirect(returnUrl);
        }
        if (result.IsLockedOut) return RedirectToPage("./Lockout");

        // Unknown key: offer a new account.
        ReturnUrl = returnUrl;
        Load(info);
        return Page();
    }

    public async Task<IActionResult> OnPostConfirmationAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");
        var info = await signInManager.GetExternalLoginInfoAsync();
        if (info is null)
        {
            ErrorMessage = "Error loading external login information during confirmation.";
            return RedirectToPage("./Login", new { ReturnUrl = returnUrl });
        }

        if (ModelState.IsValid)
        {
            // The npub is unique per key and uses only characters that Identity allows in user names.
            var userName = info.Principal.FindFirstValue(NostrClaimTypes.Npub) ?? info.ProviderKey;
            var user = new IdentityUser { UserName = userName, Email = string.IsNullOrWhiteSpace(Input.Email) ? null : Input.Email };
            var result = await userManager.CreateAsync(user);
            if (result.Succeeded)
            {
                result = await userManager.AddLoginAsync(user, info);
                if (result.Succeeded)
                {
                    await SyncProfileAsync(user, info);
                    logger.LogInformation("User created an account with {Provider}.", info.LoginProvider);
                    await signInManager.SignInAsync(user, isPersistent: false, info.LoginProvider);
                    return LocalRedirect(returnUrl);
                }
            }
            foreach (var error in result.Errors) ModelState.AddModelError(string.Empty, error.Description);
        }

        ReturnUrl = returnUrl;
        Load(info);
        return Page();
    }

    /// <summary>
    /// The Identity cookie carries claims from the database only, not the claims of the external
    /// login. So copy the Nostr profile name and picture into AspNetUserClaims at each login.
    /// Display data only: the user can change it on Nostr at any time.
    /// </summary>
    /// <returns>True when a claim changed, so the cookie needs a refresh.</returns>
    private async Task<bool> SyncProfileAsync(IdentityUser user, ExternalLoginInfo info)
    {
        string[] types = [NostrClaimTypes.Name, NostrClaimTypes.Picture];
        // No profile data at all usually means the relay lookup failed or timed out.
        // Keep the old values then, instead of wiping them.
        if (types.All(t => info.Principal.FindFirstValue(t) is null)) return false;

        var current = await userManager.GetClaimsAsync(user);
        var changed = false;
        foreach (var type in types)
        {
            var old = current.Where(c => c.Type == type).ToList();
            var value = info.Principal.FindFirstValue(type);
            if (old.Count == (value is null ? 0 : 1) && old.All(c => c.Value == value)) continue;
            if (old.Count > 0) await userManager.RemoveClaimsAsync(user, old);
            if (value is not null) await userManager.AddClaimAsync(user, new Claim(type, value));
            changed = true;
        }
        return changed;
    }

    private void Load(ExternalLoginInfo info)
    {
        ProviderDisplayName = info.ProviderDisplayName ?? info.LoginProvider;
        DisplayName = info.Principal.FindFirstValue(ClaimTypes.Name);
        Npub = info.Principal.FindFirstValue(NostrClaimTypes.Npub);
        Picture = info.Principal.FindFirstValue(NostrClaimTypes.Picture);
    }
}
