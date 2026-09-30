using Microsoft.EntityFrameworkCore;

namespace NostrGuestbook.Data;

public class GuestbookDb(DbContextOptions<GuestbookDb> options) : DbContext(options)
{
    public DbSet<Profile> Profiles => Set<Profile>();
    public DbSet<Message> Messages => Set<Message>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Profile>().HasKey(p => p.PubKey);
        b.Entity<Message>().HasKey(m => m.PubKey);
        b.Entity<Message>().Property(m => m.Text).HasMaxLength(Message.MaxLength);
        b.Entity<Message>().HasIndex(m => m.UpdatedAt);
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder builder) =>
        // SQLite cannot sort DateTimeOffset values. Stored as a sortable number, the wall can ORDER BY in SQL.
        builder.Properties<DateTimeOffset>().HaveConversion<Microsoft.EntityFrameworkCore.Storage.ValueConversion.DateTimeOffsetToBinaryConverter>();
}

public enum ProfileStatus { Queued, Fetching, Found, NotFound }

/// <summary>
/// Display data from the user's Nostr profile (kind 0), cached here so the public wall does not
/// ask relays on every page view. Refreshed at each login. Never used for identity: that is the key.
/// </summary>
public class Profile
{
    /// <summary>64-char lowercase hex pubkey.</summary>
    public required string PubKey { get; set; }
    public string? Name { get; set; }
    public string? Picture { get; set; }
    public string? Nip05 { get; set; }
    public bool Nip05Verified { get; set; }
    public ProfileStatus Status { get; set; }
    public DateTimeOffset? FetchedAt { get; set; }
}

public class Message
{
    /// <summary>
    /// The pubkey is the primary key, so the database itself allows one message per user.
    /// Saving again updates that one row.
    /// </summary>
    public required string PubKey { get; set; }
    public required string Text { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public const int MaxLength = 280;
}
