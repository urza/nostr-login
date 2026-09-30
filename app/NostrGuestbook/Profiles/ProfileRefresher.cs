using System.Collections.Concurrent;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using NostrAuth.Relays;
using NostrGuestbook.Data;

namespace NostrGuestbook.Profiles;

public sealed class ProfileRelayOptions
{
    public string[] Relays { get; set; } = [];
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(8);
}

/// <summary>Live state of one lookup, for the "fetching your profile" panel.</summary>
public sealed class ProfileProgress
{
    private readonly object _lock = new();
    private readonly List<ProfileFetchStep> _steps = [];

    public bool Done => FinishedAt is not null;
    public DateTimeOffset? FinishedAt { get; private set; }

    public void Add(ProfileFetchStep step)
    {
        lock (_lock)
        {
            // Each source has one line: "Started" is replaced by its result.
            _steps.RemoveAll(s => s.Source == step.Source);
            _steps.Add(step);
        }
    }

    public void Finish(DateTimeOffset now) => FinishedAt = now;

    public IReadOnlyList<ProfileFetchStep> Steps
    {
        get { lock (_lock) return _steps.ToList(); }
    }
}

/// <summary>
/// Loads Nostr profiles in the background. Login must not wait for relays (a slow relay would
/// hold the user on the login page for seconds), so login only queues the pubkey here.
/// </summary>
public sealed class ProfileRefresher(
    IServiceScopeFactory scopes,
    ProfileFetcher fetcher,
    Microsoft.Extensions.Options.IOptions<ProfileRelayOptions> options,
    TimeProvider time,
    ILogger<ProfileRefresher> logger) : BackgroundService
{
    private readonly Channel<string> _queue = Channel.CreateUnbounded<string>();
    private readonly ConcurrentDictionary<string, ProfileProgress> _progress = new();

    /// <summary>Marks the profile as queued and starts a lookup. A lookup that already runs is not started twice.</summary>
    public async Task EnqueueAsync(string pubKey, GuestbookDb db)
    {
        if (_progress.TryGetValue(pubKey, out var running) && !running.Done) return;

        // The step list is only for the live panel. Drop old ones, so memory does not grow with every user.
        var cutoff = time.GetUtcNow() - TimeSpan.FromMinutes(10);
        foreach (var (key, p) in _progress)
            if (p.FinishedAt < cutoff) _progress.TryRemove(key, out _);

        var profile = await db.Profiles.FindAsync(pubKey);
        if (profile is null) db.Profiles.Add(profile = new Profile { PubKey = pubKey });
        profile.Status = ProfileStatus.Queued;
        await db.SaveChangesAsync();

        _progress[pubKey] = new ProfileProgress();
        _queue.Writer.TryWrite(pubKey);
    }

    public ProfileProgress? GetProgress(string pubKey) => _progress.GetValueOrDefault(pubKey);

    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        // A few lookups in parallel: each one mostly waits on network, and one slow user
        // must not block the queue for everyone else.
        Parallel.ForEachAsync(_queue.Reader.ReadAllAsync(stoppingToken),
            new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = stoppingToken },
            async (pubKey, ct) => await RefreshAsync(pubKey, ct));

    private async Task RefreshAsync(string pubKey, CancellationToken ct)
    {
        var progress = _progress.GetOrAdd(pubKey, _ => new ProfileProgress());
        try
        {
            await SetStatusAsync(pubKey, ProfileStatus.Fetching, null, ct);
            var result = await fetcher.FetchAsync(pubKey, options.Value.Relays, options.Value.Timeout, ct, new InlineProgress(progress.Add));
            await SetStatusAsync(pubKey, result is null ? ProfileStatus.NotFound : ProfileStatus.Found, result, ct);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            logger.LogWarning(e, "Profile refresh for {PubKey} failed", pubKey);
            await SetStatusAsync(pubKey, ProfileStatus.NotFound, null, CancellationToken.None);
        }
        finally
        {
            progress.Finish(time.GetUtcNow());
        }
    }

    private async Task SetStatusAsync(string pubKey, ProfileStatus status, NostrProfile? result, CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<GuestbookDb>();
        var profile = await db.Profiles.FindAsync([pubKey], ct);
        if (profile is null) return;

        profile.Status = status;
        if (status is ProfileStatus.Found or ProfileStatus.NotFound) profile.FetchedAt = time.GetUtcNow();
        // Not found keeps the old values: a relay outage should not wipe a known name and picture.
        if (result is not null)
        {
            profile.Name = result.Name;
            profile.Picture = result.Picture;
            profile.Nip05 = result.Nip05;
            profile.Nip05Verified = result.Nip05Verified;
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary><see cref="Progress{T}"/> posts to the thread pool, so steps could arrive after "done". This reports in place.</summary>
    private sealed class InlineProgress(Action<ProfileFetchStep> report) : IProgress<ProfileFetchStep>
    {
        public void Report(ProfileFetchStep value) => report(value);
    }
}
