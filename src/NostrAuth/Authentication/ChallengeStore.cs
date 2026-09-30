using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace NostrAuth.Authentication;

/// <summary>
/// Single-use login challenges. An app on more than one node needs a shared implementation
/// (for example Redis with GETDEL), because the challenge and the login POST can hit different nodes.
/// </summary>
public interface IChallengeStore
{
    string Issue(TimeSpan lifetime);

    /// <summary>True exactly once for a challenge that was issued and is not expired.</summary>
    bool TryConsume(string challenge);
}

public sealed class InMemoryChallengeStore(TimeProvider time) : IChallengeStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _challenges = new();

    public string Issue(TimeSpan lifetime)
    {
        var now = time.GetUtcNow();
        // Cleanup on write keeps the dictionary small without a background timer.
        foreach (var (c, expires) in _challenges)
            if (expires < now) _challenges.TryRemove(c, out _);

        var challenge = Base64Url(RandomNumberGenerator.GetBytes(32));
        _challenges[challenge] = now + lifetime;
        return challenge;
    }

    // TryRemove is atomic, so two parallel requests with the same challenge cannot both win.
    public bool TryConsume(string challenge) =>
        _challenges.TryRemove(challenge, out var expires) && expires >= time.GetUtcNow();

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
