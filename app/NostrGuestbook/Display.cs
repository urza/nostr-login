using System.Globalization;
using NostrAuth;

namespace NostrGuestbook;

/// <summary>Small view helpers for author display.</summary>
public static class Display
{
    public static string Npub(string pubKey) => Nip19.ToNpub(pubKey);

    public static string ShortNpub(string pubKey)
    {
        var npub = Nip19.ToNpub(pubKey);
        return $"{npub[..10]}…{npub[^6..]}";
    }

    /// <summary>
    /// A gradient that is always the same for a key: a picture for users without one, and no
    /// request to a third-party avatar service.
    /// </summary>
    public static string AvatarGradient(string pubKey)
    {
        var h1 = int.Parse(pubKey[..4], NumberStyles.HexNumber) % 360;
        var h2 = (h1 + 40 + int.Parse(pubKey[4..6], NumberStyles.HexNumber) % 80) % 360;
        return $"background: linear-gradient(135deg, hsl({h1} 75% 60%), hsl({h2} 70% 42%))";
    }

    public static string Iso(DateTimeOffset t) => t.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
    public static string Utc(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
}
