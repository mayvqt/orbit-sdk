using System.Security.Cryptography;
using System.Text.Json;

namespace Orbit.Sdk;

/// <summary>Test-only/internal representation derived from an app key.</summary>
internal sealed record AppConfig(string ApiOrigin, string ApplicationId, string EnvironmentId, string Issuer,
    string? StatePath = null, string? Fingerprint = null, string? FingerprintProvider = null,
    OfflineKeys? OfflineKeys = null, SessionKeys? SessionKeys = null,
    string? PublicAppKey = null, AppKey? ParsedAppKey = null, string? AppVersion = null);

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

    /// <summary>Opens an installed client using one app key and optional local settings.</summary>
    public static Task<OrbitClient> OpenAsync(string appKey, OrbitOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var parsed = AppKey.Parse(appKey);
        var app = CreateAppConfig(parsed, options);
        ValidateApp(app);
        return OpenInstalledAsync(app, new Transport(app.ApiOrigin), cancellationToken);
    }
#if ORBIT_LOCAL_DEVELOPMENT
    /// <summary>Local-development entry point for an app key targeting literal loopback HTTP.</summary>
    public static Task<OrbitClient> OpenLocalAsync(string appKey, OrbitOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var parsed = AppKey.ParseLocal(appKey);
        var app = CreateAppConfig(parsed, options);
        ValidateApp(app);
        return OpenInstalledAsync(app, Transport.LocalLoopback(app.ApiOrigin), cancellationToken);
    }
#endif

    // Internal overloads keep deterministic installed fixtures independent of the host machine identity.
    internal static Task<OrbitClient> OpenAsync(AppConfig app, CancellationToken cancellationToken = default)
    {
        ValidateApp(app);
        return OpenInstalledAsync(app, new Transport(app.ApiOrigin), cancellationToken);
    }
#if ORBIT_LOCAL_DEVELOPMENT
    internal static Task<OrbitClient> OpenLocalAsync(AppConfig app, CancellationToken cancellationToken = default)
    {
        ValidateApp(app);
        return OpenInstalledAsync(app, Transport.LocalLoopback(app.ApiOrigin), cancellationToken);
    }
#endif

    private static AppConfig CreateAppConfig(AppKey key, OrbitOptions? options)
    {
        options ??= new OrbitOptions();
        var fingerprint = ResolveFingerprint(key, options);
        if (options.OfflineKeys != null && options.OfflineKeys.Environment != key.Environment)
            throw new OrbitException(OrbitError.Configuration, "invalid_offline_keys");
        if (options.SessionKeys != null && options.SessionKeys.Environment != key.Environment)
            throw new OrbitException(OrbitError.Configuration, "invalid_session_keys");
        return new AppConfig(key.ApiOrigin, key.ApplicationId, key.EnvironmentId, key.Issuer,
            options.StatePath, fingerprint?.Value, fingerprint?.Provider, options.OfflineKeys,
            options.SessionKeys, key.PublicKey(), key, Orbit.Sdk.AppVersion.Configured(options.AppVersion));
    }
    internal static Fingerprint? ResolveFingerprint(AppKey key, OrbitOptions? options)
    {
        options ??= new OrbitOptions();
        if (options.DisableMachineBinding && options.Fingerprint != null)
            throw new OrbitException(OrbitError.Configuration);
        if (options.Fingerprint != null)
            return options.Fingerprint;
        if (options.DisableMachineBinding)
            return null;
        try { return new Fingerprint(DeviceIdentity.NativeFingerprint(key.ApplicationId, key.EnvironmentId), DeviceIdentity.Provider); }
        catch (OrbitException error) when (error.Error == OrbitError.Denied && error.Code == "device_identity_unavailable") { return null; }
    }
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
                else if (OperatingSystem.IsMacOS())
                    root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Library", "Application Support", "Orbit");
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
            else if (OperatingSystem.IsMacOS())
                files = new InstalledMacOSFiles(path);
            else
                throw new OrbitException(OrbitError.Storage);
            storage = new InstalledStorage(files, scope, app.Fingerprint, app.FingerprintProvider);
            var record = storage.Record;
            client = new OrbitClient(config, new Device(record.Installation.Id, app.Fingerprint, app.FingerprintProvider), transport, storage, true)
            {
                installed = storage,
                lifetime = new InstalledLifetime(),
                offlineKeys = app.OfflineKeys,
                publicAppKey = app.PublicAppKey,
                offlineAppKey = app.ParsedAppKey,
                sessionKeys = app.SessionKeys,
                environmentName = app.ParsedAppKey?.Environment,
                appVersion = Orbit.Sdk.AppVersion.Configured(app.AppVersion)
            };
            transport.InstallationCancellation = client.lifetime.Cancellation.Token;
            if (record.PendingActivation != null)
                storage.DropCache();
            else
                await client.RestoreInstalledAsync(record).ConfigureAwait(false);
            client.RestoreOffline(record);
            if (record.Credential != null && record.PendingActivation == null)
            {
                try
                {
                    await client.RefreshAsync(cancellationToken).ConfigureAwait(false);
                }
                // An unsupported application version still opens, so the application
                // can report the denial and use update checks.
                catch (OrbitException error) when (error.Error is OrbitError.Transient or OrbitError.AppVersionUnsupported) { }
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

    /// <summary>Returns the public, serializable installation request for authenticated offline issuance.</summary>
    public OfflineRequest CreateOfflineRequest()
    {
        lock (gate)
        {
            SyncStorage();
            if (installed == null || publicAppKey == null)
                throw new OrbitException(OrbitError.Configuration);
            return new OfflineRequest("orbit-offline-request", 1, publicAppKey, device.InstallationId,
                device.Fingerprint, device.FingerprintProvider);
        }
    }

    /// <summary>Verifies and durably selects a signed offline file without network access.</summary>
    public Snapshot ImportOfflineFile(string signedFile, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signedFile);
        if (signedFile.Length is 0 or > OfflineKeys.MaximumFileBytes || signedFile.Any(c => !char.IsAscii(c)))
            throw new OrbitException(OrbitError.InvalidResponse, "invalid_offline_file");
        if (installed == null || offlineKeys == null || offlineAppKey == null)
            throw new OrbitException(OrbitError.Configuration);
        using var ownedOperation = InstallationOperation(cancellationToken);
        var operationToken = ownedOperation?.Token ?? cancellationToken;
        OrbitException.CheckCancellation(operationToken);
        var expectedGeneration = Generation();
#if ORBIT_LOCAL_DEVELOPMENT
        InstalledStorageDiagnostics.OfflineImportQueued?.Invoke();
#endif
        try { serial.Wait(operationToken); }
        catch (OperationCanceledException) { throw new OrbitException(OrbitError.Cancelled); }
        try
        {
            lock (gate)
            {
                CheckGeneration(expectedGeneration);
                OrbitException.CheckCancellation(operationToken);
                var previous = installed.OfflineState();
                var start = Clock.Capture();
                var wall = start.WallSeconds;
                if (wall < 0 || wall > OfflineKeys.MaximumTime)
                    throw new OrbitException(OrbitError.ClockUncertain, "clock_uncertain");
                var minimum = previous?.Sequence ?? 1;
                var highTime = previous?.TimeHighWater ?? 0;
                var highWall = previous?.WallHighWater ?? 0;
                if (offlineClock is { } retained)
                {
                    highTime = Math.Max(highTime, retained.TimeHighWater);
                    highWall = Math.Max(highWall, retained.WallHighWater);
                }
                if (wall + 30 < highWall)
                    throw new OrbitException(OrbitError.ClockUncertain, "clock_uncertain");
                var now = Math.Max(wall, highTime);
                if (offlineClock is { } retainedClock)
                {
                    var anchoredNow = retainedClock.Anchor.Now();
                    if (anchoredNow < highTime || wall < highWall - 30)
                        throw new OrbitException(OrbitError.ClockUncertain, "clock_uncertain");
                    now = Math.Max(now, anchoredNow);
                }
                var verified = offlineKeys.Verify(signedFile,
                    new OfflineExpected(offlineAppKey, device, now, minimum));
                if (previous != null && verified.Sequence == previous.Sequence &&
                    (verified.IssuanceId != previous.IssuanceId || verified.ContentDigest != previous.ContentDigest))
                    throw new OrbitException(OrbitError.Denied, "offline_sequence");
                OrbitException.CheckCancellation(operationToken);
                var trusted = Math.Max(now, verified.IssuedAt);
                var anchor = offlineClock?.Anchor.AdvanceFloor(trusted) ?? new ClockAnchor(trusted, start);
                var saved = new InstalledOffline(signedFile.Trim(' ', '\t', '\r', '\n', '\v', '\f'),
                    verified.Sequence, verified.IssuanceId, verified.ContentDigest, now, trusted,
                    Math.Max(highWall, wall));
                storageVersion = installed.SaveOffline(storageVersion, saved);
                offlineClock = new OfflineClockState(anchor, saved.TimeHighWater, saved.WallHighWater);
                Clear();
                try
                {
                    var current = anchor.Now();
                    var currentWall = Clock.Capture().WallSeconds;
                    if (currentWall + 30 < saved.WallHighWater || current < saved.TimeHighWater)
                        throw new OrbitException(OrbitError.ClockUncertain, "clock_uncertain");
                    if (operationToken.IsCancellationRequested)
                        throw new OrbitException(OrbitError.Cancelled);
                    var updated = saved with
                    {
                        TimeHighWater = Math.Max(saved.TimeHighWater, current),
                        WallHighWater = Math.Max(saved.WallHighWater, currentWall)
                    };
                    if (updated != saved)
                        installed.CheckpointOffline(updated);
                    offlineClock = new OfflineClockState(anchor, updated.TimeHighWater,
                        updated.WallHighWater, LastCheckpointElapsedTicks: Clock.ElapsedTicks());
                    var afterWrite = anchor.Now();
                    var afterWall = Clock.Capture().WallSeconds;
                    if (afterWall + 30 < updated.WallHighWater || afterWrite < updated.TimeHighWater)
                        throw new OrbitException(OrbitError.ClockUncertain, "clock_uncertain");
                    if (afterWrite >= verified.ExpiresAt)
                        throw new OrbitException(OrbitError.Denied, "offline_file_expired");
                    if (operationToken.IsCancellationRequested)
                        throw new OrbitException(OrbitError.Cancelled);
                    offline = new OfflineRuntime(verified, anchor, updated,
                        LastCheckpointElapsedTicks: Clock.ElapsedTicks());
                    offlineFileMode = true;
                    lifetime?.Signal();
                    var snapshot = SnapshotOfflineLocked();
                    if (operationToken.IsCancellationRequested)
                        throw new OrbitException(OrbitError.Cancelled);
                    return snapshot;
                }
                catch (OrbitException error) when (error.Error is OrbitError.Cancelled or OrbitError.ClockUncertain ||
                    error.Error == OrbitError.Denied && error.Code == "offline_file_expired")
                {
                    try { storageVersion = installed.Invalidate(); }
                    catch { Clear(); throw new OrbitException(OrbitError.Storage); }
                    Clear();
                    throw;
                }
                catch
                {
                    try { storageVersion = installed.Invalidate(); }
                    catch { }
                    Clear();
                    throw new OrbitException(OrbitError.Storage);
                }
            }
        }
        finally { serial.Release(); }
    }

    private void RestoreOffline(InstalledRecord record)
    {
        if (record.Offline is not { } saved)
            return;
        var start = Clock.Capture();
        var trustedNow = Math.Max(saved.TimeHighWater, start.WallSeconds);
        var restoredAnchor = new ClockAnchor(trustedNow, start);
        var uncertain = start.WallSeconds + 30 < saved.WallHighWater ||
            saved.TimeHighWater < saved.VerifiedAt;
        var restoredClock = new OfflineClockState(restoredAnchor, saved.TimeHighWater,
            saved.WallHighWater, uncertain, Clock.ElapsedTicks());
        offlineClock = restoredClock;
        if (saved.Jws is not { } token)
            return;
        offlineFileMode = true;
        if (offlineKeys == null || offlineAppKey == null)
            throw new OrbitException(OrbitError.Configuration, "offline_keys_required");
        try
        {
            var verified = offlineKeys.Verify(token,
                new OfflineExpected(offlineAppKey, device, saved.VerifiedAt, saved.Sequence));
            if (verified.Sequence != saved.Sequence || verified.IssuanceId != saved.IssuanceId ||
                verified.ContentDigest != saved.ContentDigest || saved.VerifiedAt < verified.IssuedAt - 30 ||
                saved.VerifiedAt >= verified.ExpiresAt)
                throw new OrbitException(OrbitError.Storage);
            offline = new OfflineRuntime(verified, restoredAnchor, saved, uncertain,
                restoredClock.LastCheckpointElapsedTicks);
        }
        catch (Exception error) when (error is OrbitException or OverflowException)
        {
            if (error is OrbitException { Error: OrbitError.Configuration }) throw;
            throw new OrbitException(OrbitError.Storage, "offline_state_invalid");
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
                saved.CredentialExpiresAt == 0 ? null : saved.CredentialExpiresAt, access.LicenceExpiresAt,
                access.ReceivedServerTime, AllowUnboundFingerprint: true)).ConfigureAwait(false);
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
        if (offlineFileMode && offline is { } offlineRuntime)
        {
            var continuity = offlineClock ?? new OfflineClockState(offlineRuntime.Anchor,
                offlineRuntime.Saved.TimeHighWater, offlineRuntime.Saved.WallHighWater,
                offlineRuntime.Uncertain, offlineRuntime.LastCheckpointElapsedTicks);
            if (!force && Clock.ElapsedTicks() - continuity.LastCheckpointElapsedTicks < TimeSpan.TicksPerMinute)
                return;
            try
            {
                var now = continuity.Anchor.Now();
                var wall = Clock.Capture().WallSeconds;
                if (now < continuity.TimeHighWater || wall < continuity.WallHighWater - 30)
                    throw new OrbitException(OrbitError.ClockUncertain, "clock_uncertain");
                var saved = offlineRuntime.Saved with
                {
                    TimeHighWater = Math.Max(continuity.TimeHighWater, now),
                    WallHighWater = Math.Max(continuity.WallHighWater, wall)
                };
                // Snapshots advance the in-memory floor without performing IO.
                // Compare against the durable copy so a later transition still
                // checkpoints every elapsed second before clearing authority.
                if (installed!.OfflineState() is not { } persisted || saved != persisted)
                    installed!.CheckpointOffline(saved);
                var elapsed = Clock.ElapsedTicks();
                offlineClock = continuity with
                {
                    TimeHighWater = saved.TimeHighWater,
                    WallHighWater = saved.WallHighWater,
                    Uncertain = false,
                    LastCheckpointElapsedTicks = elapsed
                };
                offline = offlineRuntime with
                {
                    Anchor = continuity.Anchor,
                    Saved = saved,
                    Uncertain = false,
                    LastCheckpointElapsedTicks = elapsed
                };
                lifetime!.LastCheckpoint = elapsed;
            }
            catch (OrbitException)
            {
                offlineClock = continuity with { Uncertain = true };
                offline = offlineRuntime with { Uncertain = true };
                throw;
            }
            return;
        }
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
        long expectedGeneration;
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
            var snapshot = client.SnapshotLocked();
            var sessionDue = false;
            if (!client.offlineFileMode && client.sessionRequired && !client.sessionDisabled && client.credential != null)
            {
                try
                {
                    sessionDue = client.sessionRetryElapsedTicks == 0 ||
                        Clock.ElapsedTicks() >= client.sessionRetryElapsedTicks;
                    if (sessionDue && client.sessionGrant != null && client.sessionAnchor != null)
                        sessionDue = client.sessionAnchor.Now() >= client.sessionGrant.RefreshAfter;
                }
                catch (OrbitException) { sessionDue = true; }
            }
            expectedGeneration = client.generation;
            due = sessionDue || client.credential != null && !client.sessionRequired &&
                (snapshot.Access is Access.RefreshRequired or Access.Expired or Access.Offline) && client.RetryDueLocked();
        }
        if (due)
        {
            try
            {
                await client.RefreshIfDueAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OrbitException)
            {
                lock (client.gate)
                {
                    if (client.generation == expectedGeneration && client.sessionRequired && !client.sessionDisabled)
                    {
                        try
                        {
                            client.sessionRetryElapsedTicks = Math.Max(client.sessionRetryElapsedTicks,
                                checked(Clock.ElapsedTicks() + 30 * TimeSpan.TicksPerSecond));
                        }
                        catch (Exception error) when (error is OrbitException or OverflowException)
                        { client.sessionRetryElapsedTicks = long.MaxValue; }
                    }
                }
            }
        }
        lock (client.gate)
        {
            if (client.disposed != 0)
                return Timeout.InfiniteTimeSpan;
            if (client.offlineFileMode && client.offline != null)
            {
                var checkpoint = client.lifetime!.LastCheckpoint + TimeSpan.TicksPerMinute - Clock.ElapsedTicks();
                return TimeSpan.FromTicks(Math.Clamp(checkpoint, TimeSpan.TicksPerMillisecond * 10, TimeSpan.TicksPerMinute));
            }
            if (client.credential == null)
                return Timeout.InfiniteTimeSpan;
            var nowTicks = Clock.ElapsedTicks();
            if (client.sessionRequired)
            {
                if (client.sessionDisabled) return Timeout.InfiniteTimeSpan;
                if (client.sessionRetryElapsedTicks > nowTicks)
                    return TimeSpan.FromTicks(Math.Clamp(client.sessionRetryElapsedTicks - nowTicks,
                        TimeSpan.TicksPerMillisecond * 10, TimeSpan.TicksPerMinute));
                if (client.sessionGrant == null || client.sessionAnchor == null)
                    return TimeSpan.FromMilliseconds(10);
                try
                {
                    var until = checked((client.sessionGrant.RefreshAfter - client.sessionAnchor.Now()) * TimeSpan.TicksPerSecond);
                    return TimeSpan.FromTicks(Math.Clamp(until, TimeSpan.TicksPerMillisecond * 10, TimeSpan.TicksPerMinute));
                }
                catch (OrbitException) { return TimeSpan.FromMilliseconds(10); }
                catch (OverflowException) { return TimeSpan.FromMilliseconds(10); }
            }
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
            StoredCredential? releaseCredential;
            string? releaseId;
            lock (gate)
            {
                releaseCredential = credential;
                releaseId = sessionGrant?.SessionId ?? pendingSessionId;
                sessionGrant = null;
                sessionAnchor = null;
                pendingSessionId = null;
                pendingRenewalSequence = null;
                try
                {
                    CheckpointInstalled(true);
                }
                catch (Exception error) { failure ??= error; }
                disposed = 1;
                Clear();
            }
            if (releaseCredential != null && releaseId != null)
            {
                transport.InstallationCancellation = null;
                try
                {
                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    await transport.PostAsync($"/api/client/v1/activations/{releaseCredential.ActivationId}/sessions/{releaseId}/end",
                        CredentialBody(releaseCredential), false, timeout.Token).ConfigureAwait(false);
                }
                catch { }
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
