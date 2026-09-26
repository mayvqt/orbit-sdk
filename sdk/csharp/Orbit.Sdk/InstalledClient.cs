using System.Security.Cryptography;
using System.Text.Json;

namespace Orbit.Sdk;

/// <summary>Public application configuration. StatePath names an optional dedicated absolute directory.</summary>
public sealed record AppConfig(string ApiOrigin, string ApplicationId, string EnvironmentId, string Issuer,
    string? StatePath = null, string? Fingerprint = null, string? FingerprintProvider = null);

internal sealed class InstalledLifetime
{
    internal readonly CancellationTokenSource Cancellation = new();
    internal readonly SemaphoreSlim Wake = new(0, 1);
    internal Task Worker = Task.CompletedTask;
    internal long LastCheckpoint = Clock.ElapsedTicks();
    internal bool Restoring;
    internal void Signal()
    {
        try
        {
            Wake.Release();
        }
        catch (SemaphoreFullException) { }
    }
}

public sealed partial class OrbitClient : IAsyncDisposable
{
    private InstalledStorage? installed;
    private InstalledLifetime? lifetime;
    private Task? closeTask;

    /// <summary>Opens a remembered installation and starts automatic validation.</summary>
    public static Task<OrbitClient> OpenAsync(AppConfig app, CancellationToken cancellationToken = default)
    {
        ValidateApp(app);
        return OpenInstalledAsync(app, new Transport(app.ApiOrigin), cancellationToken);
    }
#if ORBIT_LOCAL_DEVELOPMENT
    /// <summary>Explicit local-development equivalent, restricted to literal loopback HTTP.</summary>
    public static Task<OrbitClient> OpenLocalAsync(AppConfig app, CancellationToken cancellationToken = default)
    {
        ValidateApp(app);
        return OpenInstalledAsync(app, Transport.LocalLoopback(app.ApiOrigin), cancellationToken);
    }
#endif
    private static void ValidateApp(AppConfig app)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (app.ApiOrigin == null || app.Issuer == null || app.ApplicationId == null || app.EnvironmentId == null)
            throw new OrbitException(OrbitError.Configuration);
        new OrbitConfig(app.ApplicationId, app.EnvironmentId, app.Issuer).Validate(new Device("installation_validation", app.Fingerprint, app.FingerprintProvider));
    }
    private static async Task<OrbitClient> OpenInstalledAsync(AppConfig app, Transport transport, CancellationToken cancellationToken)
    {
        IInstalledFiles? files = null;
        InstalledStorage? storage = null;
        OrbitClient? client = null;
        try
        {
            OrbitException.CheckCancellation(cancellationToken);
            var config = new OrbitConfig(app.ApplicationId, app.EnvironmentId, app.Issuer);
            var scope = new InstalledScope(transport.CanonicalOrigin, app.Issuer, app.ApplicationId, app.EnvironmentId);
            var entropy = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(scope, InstalledCodec.Options));
            var path = app.StatePath;
            if (path == null)
            {
                string root;
                if (OperatingSystem.IsWindows())
                    root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Orbit");
                else if (OperatingSystem.IsLinux())
                {
                    var selected = Environment.GetEnvironmentVariable("XDG_STATE_HOME");
                    root = string.IsNullOrEmpty(selected) ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "state") : selected;
                    root = Path.Combine(root, "orbit");
                }
                else
                    throw new OrbitException(OrbitError.Storage);
                path = Path.Combine(root, Convert.ToHexStringLower(entropy));
            }
            if (!Path.IsPathFullyQualified(path))
                throw new OrbitException(OrbitError.Configuration);
            if (OperatingSystem.IsWindows())
                files = new InstalledWindowsFiles(path, entropy);
            else if (OperatingSystem.IsLinux())
                files = new InstalledLinuxFiles(path);
            else
                throw new OrbitException(OrbitError.Storage);
            storage = new InstalledStorage(files, scope, app.Fingerprint, app.FingerprintProvider);
            var record = storage.Record;
            client = new OrbitClient(config, new Device(record.Installation.Id, app.Fingerprint, app.FingerprintProvider), transport, storage, true)
            {
                installed = storage,
                lifetime = new InstalledLifetime()
            };
            transport.InstallationCancellation = client.lifetime.Cancellation.Token;
            if (record.PendingActivation != null)
                storage.DropCache();
            else
                await client.RestoreInstalledAsync(record).ConfigureAwait(false);
            if (record.Credential != null && record.PendingActivation == null)
            {
                try
                {
                    await client.RefreshAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OrbitException error) when (error.Error == OrbitError.Transient) { }
            }
            var weak = new WeakReference<OrbitClient>(client);
            client.lifetime.Worker = RunInstalledAsync(weak, client.lifetime, storage, transport);
            return client;
        }
        catch (Exception error)
        {
            client?.lifetime?.Cancellation.Cancel();
            if (storage != null)
                storage.Dispose();
            else
                files?.Dispose();
            transport.Dispose();
            if (error is OrbitException)
                throw;
            throw new OrbitException(OrbitError.Storage);
        }
    }

    private async Task RestoreInstalledAsync(InstalledRecord record)
    {
        if (record.Access is not { } access || record.Stored is not { } saved)
            return;
        var valid = false;
        try
        {
            var restoredKeys = GrantKeys.Parse(access.Jwks);
            var grant = await restoredKeys.VerifyAsync(access.Jws, new GrantExpected(config, device, saved.LicenceId, saved.ActivationId,
                saved.CredentialExpiresAt == 0 ? null : saved.CredentialExpiresAt, access.LicenceExpiresAt, access.ReceivedServerTime)).ConfigureAwait(false);
            var start = Clock.Capture();
            if (start.WallSeconds < access.WallHighWater || access.WallHighWater < access.ReceivedWallTime || access.ServerHighWater < access.ReceivedServerTime ||
                Math.Abs(checked((access.ServerHighWater - access.ReceivedServerTime) - (access.WallHighWater - access.ReceivedWallTime))) > 30)
                return;
            var now = Math.Max(access.ServerHighWater, checked(access.ReceivedServerTime + start.WallSeconds - access.ReceivedWallTime));
            if (now < grant.IssuedAt || now >= grant.ExpiresAt || saved.CredentialExpiresAt != 0 && now >= saved.CredentialExpiresAt)
                return;
            keys = restoredKeys;
            claims = grant;
            anchor = new ClockAnchor(now, start);
            transient = true;
            lifetime!.Restoring = true;
            valid = true;
        }
        catch (Exception error) when (error is OrbitException or OverflowException) { }
        finally { if (!valid) installed!.DropCache(); }
    }
    private CancellationTokenSource? InstallationOperation(CancellationToken cancellationToken) => lifetime == null ? null :
        CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Cancellation.Token);

    private void CheckpointInstalled(bool force)
    {
        if (installed == null || lifetime == null || claims == null || anchor == null)
            return;
        if (!force && Clock.ElapsedTicks() - lifetime.LastCheckpoint < TimeSpan.TicksPerMinute)
            return;
        try
        {
            installed.Checkpoint(anchor.Now(), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            lifetime.LastCheckpoint = Clock.ElapsedTicks();
        }
        catch (OrbitException error)
        {
            claims = null;
            anchor = null;
            if (error.Error == OrbitError.ClockUncertain)
                installed.DropCache();
            throw;
        }
    }
    private static async Task RunInstalledAsync(WeakReference<OrbitClient> weak, InstalledLifetime life, InstalledStorage storage, Transport transport)
    {
        try
        {
            while (!life.Cancellation.IsCancellationRequested)
            {
                TimeSpan delay;
                try
                {
                    delay = await InstalledTickAsync(weak, life.Cancellation.Token).ConfigureAwait(false);
                }
                catch (OrbitException) { delay = TimeSpan.FromSeconds(30); }
                if (delay == TimeSpan.MinValue)
                    return;
                await life.Wake.WaitAsync(delay, life.Cancellation.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            if (!weak.TryGetTarget(out _))
            {
                storage.Dispose();
                transport.Dispose();
            }
        }
    }
    private static async Task<TimeSpan> InstalledTickAsync(WeakReference<OrbitClient> weak, CancellationToken cancellationToken)
    {
        if (!weak.TryGetTarget(out var client))
            return TimeSpan.MinValue;
        bool due;
        lock (client.gate)
        {
            try
            {
                client.SyncStorage();
            }
            catch (OrbitException) { return Timeout.InfiniteTimeSpan; }
            try
            {
                client.CheckpointInstalled(false);
            }
            catch (OrbitException error) when (error.Error == OrbitError.ClockUncertain) { }
            catch (OrbitException) { return Timeout.InfiniteTimeSpan; }
            if (client.installed?.Record.PendingActivation != null)
                return Timeout.InfiniteTimeSpan;
            var snapshot = client.SnapshotState();
            due = client.credential != null && (snapshot.Access is Access.RefreshRequired or Access.Expired or Access.Offline) && client.RetryDueLocked();
        }
        if (due)
        {
            try
            {
                await client.RefreshIfDueAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OrbitException) { }
        }
        lock (client.gate)
        {
            if (client.credential == null || client.disposed != 0)
                return Timeout.InfiniteTimeSpan;
            var nowTicks = Clock.ElapsedTicks();
            if (client.nextRetryElapsedTicks == long.MaxValue)
                client.nextRetryElapsedTicks = checked(nowTicks + 30 * TimeSpan.TicksPerSecond);
            var ticks = client.nextRetryElapsedTicks > nowTicks ? client.nextRetryElapsedTicks - nowTicks : TimeSpan.TicksPerSecond;
            if (client.nextRetryElapsedTicks <= nowTicks && client.claims != null && client.anchor != null)
            {
                try
                {
                    ticks = Math.Max(TimeSpan.TicksPerSecond, checked((client.claims.RefreshAfter - client.anchor.Now()) * TimeSpan.TicksPerSecond));
                }
                catch (OrbitException) { }
            }
            if (client.claims != null && client.anchor != null)
                ticks = Math.Min(ticks, client.lifetime!.LastCheckpoint + TimeSpan.TicksPerMinute - nowTicks);
            return TimeSpan.FromTicks(Math.Clamp(ticks, TimeSpan.TicksPerMillisecond * 10, TimeSpan.TicksPerMinute));
        }
    }
    public ValueTask DisposeAsync()
    {
        lock (gate)
            return new ValueTask(closeTask ??= CloseInstalledAsync());
    }
    private async Task CloseInstalledAsync()
    {
        if (lifetime == null)
        {
            if (ownsTransport && Interlocked.Exchange(ref disposed, 1) == 0)
                transport.Dispose();
            return;
        }
        lifetime.Cancellation.Cancel();
        Exception? failure = null;
        try
        {
            await lifetime.Worker.ConfigureAwait(false);
        }
        catch (Exception error) { failure = error; }
        await serial.WaitAsync().ConfigureAwait(false);
        try
        {
            lock (gate)
            {
                try
                {
                    CheckpointInstalled(true);
                }
                catch (Exception error) { failure ??= error; }
                disposed = 1;
                Clear();
            }
        }
        finally { serial.Release(); }
        try
        {
            await transport.SettleInstalledAsync().ConfigureAwait(false);
        }
        finally
        {
            try
            {
                installed!.Dispose();
            }
            finally { transport.Dispose(); GC.SuppressFinalize(this); }
        }
        if (failure != null)
            throw failure;
    }
    ~OrbitClient()
    {
        lifetime?.Cancellation.Cancel();
    }
}
