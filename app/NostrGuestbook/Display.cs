using System.Globalization;
using System.Reflection;
using NostrAuth;

namespace NostrGuestbook;

/// <summary>Small view helpers for author display.</summary>
public static class Display
{
    /// <summary>
    /// Git commit of this build, or null for a build without one. The .NET SDK appends
    /// "+&lt;SourceRevisionId&gt;" to the informational version: from git when built from source,
    /// from the GIT_SHA build argument in Docker (the image build has no .git folder).
    /// </summary>
    public static readonly string? Commit =
        typeof(Display).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion is { } v
        && v.IndexOf('+') is var i and >= 0 && v[(i + 1)..] is { Length: >= 7 } sha && sha.All(Uri.IsHexDigit)
            ? sha.ToLowerInvariant()
            : null;

    public static string Version => Commit?[..7] ?? "dev";

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
