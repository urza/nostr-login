using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Demo.IdentityLink.Data;

var builder = WebApplication.CreateBuilder(args);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(connectionString));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

// RequireConfirmedAccount is off because this demo has no email sender. A Nostr-only account has no email at all.
builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = false)
    .AddEntityFrameworkStores<ApplicationDbContext>();

// The only Nostr-specific line. Identity already set DefaultSignInScheme to its external cookie,
// so Nostr acts like Google or GitHub: it shows up on the login page and under
// Manage > External logins, and the pubkey lands in AspNetUserLogins (LoginProvider "Nostr").
builder.Services.AddAuthentication().AddNostr(o =>
{
    o.AppName = "Identity link demo";
    o.PublicOrigin = builder.Configuration["Nostr:PublicOrigin"];
    // Replace, not bind: the configuration binder appends to a list that already has default items.
    if (builder.Configuration.GetSection("Nostr:NostrConnectRelays").Get<string[]>() is { Length: > 0 } relays)
        o.NostrConnectRelays = relays;
});
builder.Services.AddRazorPages();

var app = builder.Build();

// Demo convenience: create or update the SQLite database on start.
using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.Migrate();

if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error");
}

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.Run();
