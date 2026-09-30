using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using NostrAuth.Authentication;
using NostrGuestbook.Data;
using NostrGuestbook.Profiles;

namespace NostrGuestbook.Pages;

public class IndexModel(GuestbookDb db, ProfileRefresher refresher, TimeProvider time) : PageModel
{
    public const int WallSize = 200;

    public sealed record Entry(Message Message, Profile? Author);

    public IReadOnlyList<Entry> Wall { get; private set; } = [];
    public int TotalMessages { get; private set; }
    public string? MyPubKey { get; private set; }
    public Profile? MyProfile { get; private set; }
    public Message? MyMessage { get; private set; }

    [BindProperty]
    public string? Text { get; set; }

    [TempData] public string? Notice { get; set; }

    // The page is public, so [Authorize] cannot go on the class, and Razor Pages ignore it on
    // handler methods. Each POST handler checks this instead.
    private string? Me => User.FindFirstValue(NostrClaimTypes.PubKey);

    public async Task OnGetAsync()
    {
        MyPubKey = Me;
        if (MyPubKey is not null)
        {
            MyProfile = await db.Profiles.FindAsync(MyPubKey);
            MyMessage = await db.Messages.FindAsync(MyPubKey);
            Text ??= MyMessage?.Text;
        }

        TotalMessages = await db.Messages.CountAsync();
        var messages = await db.Messages.AsNoTracking().OrderByDescending(m => m.UpdatedAt).Take(WallSize).ToListAsync();
        var keys = messages.Select(m => m.PubKey).ToList();
        var profiles = await db.Profiles.AsNoTracking().Where(p => keys.Contains(p.PubKey)).ToDictionaryAsync(p => p.PubKey);
        Wall = messages.Select(m => new Entry(m, profiles.GetValueOrDefault(m.PubKey))).ToList();
    }

    public async Task<IActionResult> OnPostSaveAsync()
    {
        if (Me is not { } pubKey) return Challenge();
        // Normalize line breaks, trim, and limit blank lines, so the wall stays readable.
        var text = System.Text.RegularExpressions.Regex.Replace((Text ?? "").Replace("\r\n", "\n").Trim(), "\n{3,}", "\n\n");
        // Check the length after normalization: the browser sends each line break as \r\n (2 chars),
        // but the textarea counter and the stored text count it as 1.
        if (text.Length == 0) ModelState.AddModelError(nameof(Text), "Write something first.");
        if (text.Length > Message.MaxLength) ModelState.AddModelError(nameof(Text), $"A message can have at most {Message.MaxLength} characters.");
        if (!ModelState.IsValid)
        {
            await OnGetAsync();
            return Page();
        }

        var now = time.GetUtcNow();
        var message = await db.Messages.FindAsync(pubKey);
        if (message is null)
        {
            db.Messages.Add(new Message { PubKey = pubKey, Text = text, CreatedAt = now, UpdatedAt = now });
            Notice = "Your message is on the wall.";
        }
        else if (message.Text != text)
        {
            message.Text = text;
            message.UpdatedAt = now;
            Notice = "Your message is updated.";
        }
        await db.SaveChangesAsync();
        return Redirect("/#me");
    }

    public async Task<IActionResult> OnPostDeleteAsync()
    {
        if (Me is not { } pubKey) return Challenge();
        if (await db.Messages.FindAsync(pubKey) is { } message)
        {
            db.Messages.Remove(message);
            await db.SaveChangesAsync();
            Notice = "Your message is deleted.";
        }
        return Redirect("/#me");
    }

    public async Task<IActionResult> OnPostRefreshAsync()
    {
        if (Me is not { } pubKey) return Challenge();
        await refresher.EnqueueAsync(pubKey, db);
        return Redirect("/#me");
    }

    public async Task<IActionResult> OnPostLogoutAsync()
    {
        await HttpContext.SignOutAsync();
        return Redirect("/");
    }
}
