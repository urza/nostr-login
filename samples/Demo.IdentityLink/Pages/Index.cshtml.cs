using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Demo.IdentityLink.Pages;

public class IndexModel(UserManager<IdentityUser> userManager) : PageModel
{
    public IList<UserLoginInfo>? Logins { get; private set; }
    public bool HasPassword { get; private set; }

    public async Task OnGetAsync()
    {
        if (await userManager.GetUserAsync(User) is not { } user) return;
        Logins = await userManager.GetLoginsAsync(user);
        HasPassword = await userManager.HasPasswordAsync(user);
    }
}
