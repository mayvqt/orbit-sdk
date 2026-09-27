using System.Security.Cryptography;
using System.Text.Json;

namespace Orbit.Sdk;

/// <summary>A serialized access context. Do not share storage without atomic cross-context invalidation.</summary>
public sealed partial class OrbitClient : IDisposable
{
    private const int MinimumRetryDelaySeconds = 15;
    private const int MaximumRetryDelaySeconds = 44;
    private readonly OrbitConfig config;
    private readonly Device device;
    private readonly Transport transport;
    private readonly bool ownsTransport;
    private readonly ICredentialStorage storage;
    private readonly object gate = new();
    private readonly SemaphoreSlim serial = new(1, 1);
    private long generation;
    private long storageVersion;
    private StoredCredential? credential;
    private GrantClaims? claims;
    private ClockAnchor? anchor;
    private GrantKeys keys = new();
    private CustomerSession? session;
    private bool transient;
    private long nextRetryElapsedTicks;
    private int disposed;
    private bool offlineFileMode;
    private OfflineRuntime? offline;
    private OfflineClockState? offlineClock;
    private OfflineKeys? offlineKeys;
    private string? publicAppKey;
    private AppKey? offlineAppKey;
    private SessionKeys? sessionKeys;
    private string? environmentName;
    private bool sessionRequired;
    private bool sessionProfileKnown;
    private bool sessionDisabled;
    private SessionGrant? sessionGrant;
    private ClockAnchor? sessionAnchor;
    private string? pendingSessionId;
    private long? pendingRenewalSequence;
    private long sessionRetryElapsedTicks;
    private long? sessionLicenceExpiry;
    private string? sessionBindingMode;
    private string? appVersion;
    private string? updateAvailable;
    private OrbitException? versionDenial;

    public StorageCapability StorageCapability { get; }

    internal static OrbitClient Connect(OrbitSetup setup)
    {
        ArgumentNullException.ThrowIfNull(setup);
        var config = new OrbitConfig(setup.ApplicationId, setup.EnvironmentId, setup.Issuer);
        var device = new Device(setup.InstallationId);
        config.Validate(device);
        var transport = new Transport(setup.ApiOrigin);
        try { return new OrbitClient(config, device, transport, null, true); }
        catch { transport.Dispose(); throw; }
    }

    internal OrbitClient(OrbitConfig config, Device device, Transport transport, ICredentialStorage? storage = null)
        : this(config, device, transport, storage, false)
    {
    }

    private OrbitClient(OrbitConfig config, Device device, Transport transport, ICredentialStorage? storage, bool ownsTransport)
    {
        config.Validate(device);
        _ = Clock.ElapsedTicks();
        this.config = config;
        this.device = device;
        this.transport = transport;
        this.ownsTransport = ownsTransport;
        this.storage = storage ?? new MemoryStorage();
        try
        {
            StorageCapability = this.storage.Capability;
            (storageVersion, credential) = this.storage.Load();
        }
        catch (Exception) { throw new OrbitException(OrbitError.Storage); }
        if (storageVersion < 0 || (credential != null &&
            (credential.ApplicationId != config.ApplicationId || credential.EnvironmentId != config.EnvironmentId ||
             credential.InstallationId != device.InstallationId || credential.Fingerprint != device.Fingerprint ||
             credential.FingerprintProvider != device.FingerprintProvider || !JsonWire.Opaque(credential.ActivationId) ||
             !JsonWire.Opaque(credential.LicenceId) || !JsonWire.Bearer(credential.Credential))))
            throw new OrbitException(OrbitError.Storage);
    }

    /// <summary>Releases an internally created transport. Injected transports remain caller-owned.</summary>
    public void Dispose()
    {
        DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    public Snapshot Snapshot()
    {
        lock (gate) return SnapshotLocked();
    }

    private Snapshot SnapshotLocked()
    {
        SyncStorage();
        if (offlineFileMode)
            return SnapshotOfflineLocked();
        if (sessionRequired)
            return SnapshotSessionLocked();
        long? now = null;
        if (anchor != null)
        {
            try { now = anchor.Now(); }
            catch (OrbitException)
            {
                // Keep the credential for online reconciliation; the old grant
                // and all responses started against its clock are superseded.
                claims = null;
                anchor = null;
                generation++;
                installed?.DropCache();
                lifetime?.Signal();
            }
        }
        return SnapshotState(now);
    }

    private Snapshot SnapshotOfflineLocked()
    {
        var runtime = offline ?? throw new OrbitException(OrbitError.Storage);
        var continuity = offlineClock ?? new OfflineClockState(runtime.Anchor,
            runtime.Saved.TimeHighWater, runtime.Saved.WallHighWater, runtime.Uncertain,
            runtime.LastCheckpointElapsedTicks);
        long now;
        long wall;
        try
        {
            now = continuity.Anchor.Now();
            wall = Clock.Capture().WallSeconds;
            if (wall < continuity.WallHighWater - 30 || now < continuity.TimeHighWater)
                throw new OrbitException(OrbitError.ClockUncertain, "clock_uncertain");
        }
        catch (OrbitException error) when (error.Error == OrbitError.ClockUncertain)
        {
            offlineClock = continuity with { Uncertain = true };
            offline = runtime with { Uncertain = true };
            throw;
        }
        var highTime = Math.Max(continuity.TimeHighWater, now);
        var highWall = Math.Max(continuity.WallHighWater, wall);
        var saved = runtime.Saved with { TimeHighWater = highTime, WallHighWater = highWall };
        offlineClock = continuity with { TimeHighWater = highTime, WallHighWater = highWall, Uncertain = false };
        offline = runtime with { Saved = saved, Uncertain = false };
        var expired = now >= runtime.File.ExpiresAt;
        return new Snapshot(expired ? Access.Expired : Access.Offline,
            expired ? global::Orbit.Sdk.Snapshot.EmptyEntitlements : runtime.File.Entitlements,
            DateTimeOffset.FromUnixTimeSeconds(runtime.File.ExpiresAt), null, null, false, true,
            TimeSpan.FromSeconds(now >= runtime.File.ExpiresAt ? 0 : runtime.File.ExpiresAt - now))
        {
            PolicyVersion = runtime.File.PolicyVersion,
            OfflineFileMode = true
        };
    }

    private Snapshot SnapshotSessionLocked()
    {
        long? credentialExpiry = credential?.CredentialExpiresAt is > 0 ? credential.CredentialExpiresAt : null;
        if (sessionGrant == null || sessionAnchor == null)
            return new Snapshot(Access.RefreshRequired, global::Orbit.Sdk.Snapshot.EmptyEntitlements, null, null,
                global::Orbit.Sdk.Snapshot.FromUnixSeconds(credentialExpiry), credential == null, false, TimeSpan.Zero);
        long now;
        try { now = sessionAnchor.Now(); }
        catch (OrbitException error) when (error.Error == OrbitError.ClockUncertain)
        {
            sessionGrant = null;
            sessionAnchor = null;
            pendingRenewalSequence = null;
            generation++;
            throw;
        }
        var usable = now < sessionGrant.ExpiresAt;
        return new Snapshot(usable ? Access.Online : Access.Expired,
            usable ? sessionGrant.Entitlements : global::Orbit.Sdk.Snapshot.EmptyEntitlements,
            global::Orbit.Sdk.Snapshot.FromUnixSeconds(sessionGrant.ExpiresAt), global::Orbit.Sdk.Snapshot.FromUnixSeconds(sessionGrant.RefreshAfter),
            global::Orbit.Sdk.Snapshot.FromUnixSeconds(credentialExpiry), credentialExpiry != null && credentialExpiry <= now + 86400,
            false, TimeSpan.Zero)
        {
            PolicyVersion = sessionGrant.PolicyVersion,
            Session = new SessionInfo(sessionGrant.SessionId, sessionGrant.Sequence),
            UpdateAvailable = updateAvailable
        };
    }

    private Snapshot SnapshotState(long? now)
    {
        long? expiry = credential?.CredentialExpiresAt;
        if (expiry == 0) expiry = null;
        if (claims == null || anchor == null || now == null)
            return new Snapshot(credential == null ? Access.Denied : Access.RefreshRequired,
                global::Orbit.Sdk.Snapshot.EmptyEntitlements, null, null,
                global::Orbit.Sdk.Snapshot.FromUnixSeconds(expiry), credential == null, false, TimeSpan.Zero);
        var checkedNow = now.Value;
        var access = claims.ExpiresAt <= checkedNow ? Access.Expired : transient
            ? (claims.OfflineAllowed ? Access.Offline : Access.RefreshRequired)
            : claims.RefreshAfter <= checkedNow ? Access.RefreshRequired : Access.Online;
        var usable = access is Access.Online or Access.Offline;
        return new Snapshot(access, usable ? claims.Entitlements : global::Orbit.Sdk.Snapshot.EmptyEntitlements,
            global::Orbit.Sdk.Snapshot.FromUnixSeconds(claims.ExpiresAt),
            global::Orbit.Sdk.Snapshot.FromUnixSeconds(claims.RefreshAfter),
            global::Orbit.Sdk.Snapshot.FromUnixSeconds(expiry), expiry != null && expiry <= checkedNow + 86400,
            claims.OfflineAllowed, usable && claims.OfflineAllowed
                ? TimeSpan.FromSeconds(claims.ExpiresAt - checkedNow) : TimeSpan.Zero)
        { PolicyVersion = claims.PolicyVersion, UpdateAvailable = updateAvailable };
    }

    private void SyncStorage()
    {
        if (Volatile.Read(ref disposed) != 0)
            throw new OrbitException(OrbitError.Cancelled);
        long version;
        try { version = storage.Version; }
        catch (Exception)
        {
            Clear();
            throw new OrbitException(OrbitError.Storage);
        }
        if (version < 0) { Clear(); throw new OrbitException(OrbitError.Storage); }
        if (version != storageVersion)
        {
            Clear();
            offlineClock = null;
            storageVersion = version;
        }
    }

    private void InvalidateStorage(bool clearPending = true)
    {
        try
        {
            storageVersion = installed != null ? installed.Invalidate(clearPending) : storage.Invalidate();
            lifetime?.Signal();
        }
        catch (Exception) { Clear(); throw new OrbitException(OrbitError.Storage); }
    }

    private void CheckpointOfflineBeforeTransition()
    {
        if (!offlineFileMode || offline == null)
            return;
        try { CheckpointInstalled(true); }
        catch (OrbitException error) when (error.Error == OrbitError.ClockUncertain) { }
    }

    private long Generation()
    {
        lock (gate) { SyncStorage(); return generation; }
    }

    private void CheckGeneration(long expected)
    {
        SyncStorage();
        if (generation != expected) throw new OrbitException(OrbitError.StaleResponse);
    }

    private void Clear(bool keepAccount = false)
    {
        var releaseId = sessionGrant?.SessionId ?? pendingSessionId;
        var releaseCredential = credential;
        generation++;
        credential = null;
        claims = null;
        anchor = null;
        transient = false;
        nextRetryElapsedTicks = 0;
        offline = null;
        offlineFileMode = false;
        sessionRequired = false;
        sessionProfileKnown = false;
        sessionDisabled = false;
        sessionGrant = null;
        sessionAnchor = null;
        pendingSessionId = null;
        pendingRenewalSequence = null;
        sessionRetryElapsedTicks = 0;
        sessionLicenceExpiry = null;
        sessionBindingMode = null;
        updateAvailable = null;
        versionDenial = null;
        if (!keepAccount) session = null;
        if (releaseId != null && releaseCredential != null)
            QueueSessionRelease(releaseCredential, releaseId);
    }

    /// <summary>Clear local access and make a bounded best-effort release of any floating seat.</summary>
    public void Logout()
    {
        lock (gate) { SyncStorage(); CheckpointOfflineBeforeTransition(); Clear(); InvalidateStorage(); }
    }

    public Task<Snapshot> ActivateAsync(string licenceKey, string? idempotencyKey = null,
        CancellationToken cancellationToken = default) => ActivateWithPreviousAsync(licenceKey, null, idempotencyKey, cancellationToken);

    public Task<Snapshot> ActivateWithPreviousAsync(string licenceKey, string? previousCredential, string? idempotencyKey,
        CancellationToken cancellationToken = default) => ActivateAsAsync(licenceKey, false, previousCredential, idempotencyKey, cancellationToken);

    private async Task<Snapshot> ActivateAsAsync(string principal, bool account, string? previousCredential,
        string? idempotencyKey, CancellationToken cancellationToken)
    {
        using var ownedOperation = InstallationOperation(cancellationToken);
        cancellationToken = ownedOperation?.Token ?? cancellationToken;
        if ((account ? !JsonWire.Opaque(principal) : principal is not { Length: >= 1 and <= 256 }) ||
            (idempotencyKey != null && !JsonWire.OperationId(idempotencyKey)) || (previousCredential != null && !JsonWire.Bearer(previousCredential)))
            throw new OrbitException(OrbitError.Configuration);
        if (idempotencyKey == null && installed == null)
            idempotencyKey = Device.NewInstallation().InstallationId;
        var expected = Generation();
        await EnterSerialAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            string? customerSession;
            lock (gate)
            {
                CheckGeneration(expected);
                OrbitException.CheckCancellation(cancellationToken);
                customerSession = account ? (session?.Token ?? throw new OrbitException(OrbitError.ReauthenticationRequired)) : null;
                CheckpointOfflineBeforeTransition();
                if (installed != null)
                    (idempotencyKey, storageVersion) = installed.Begin(principal, account, previousCredential,
                        idempotencyKey, account ? session?.Account.Customer.Id : null);
                Clear(account);
                if (installed == null)
                    InvalidateStorage();
                expected = generation;
            }
            var body = DeviceBody();
            if (installed != null)
                body["credential_mode"] = "persistent";
            body["previous_credential"] = previousCredential;
            body["idempotency_key"] = idempotencyKey;
            if (account) { body["customer_session"] = customerSession; body["licence_id"] = principal; }
            else body["licence_key"] = principal;
            if (appVersion != null) body["app_version"] = appVersion;
            return await RequestGrantAsync("/api/client/v1/activations", body, expected, null,
                account ? principal : null, cancellationToken).ConfigureAwait(false);
        }
        finally { serial.Release(); }
    }

    public Task<Snapshot> RefreshAsync(CancellationToken cancellationToken = default) =>
        RefreshCoreAsync(cancellationToken, acquireSession: true);

    private async Task<Snapshot> RefreshCoreAsync(CancellationToken cancellationToken, bool acquireSession)
    {
        using var ownedOperation = InstallationOperation(cancellationToken);
        cancellationToken = ownedOperation?.Token ?? cancellationToken;
        var expected = Generation();
        await EnterSerialAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            StoredCredential saved;
            bool floating;
            lock (gate)
            {
                CheckGeneration(expected);
                OrbitException.CheckCancellation(cancellationToken);
                if (offlineFileMode)
                    return SnapshotLocked();
                if (installed?.Record.PendingActivation != null)
                    throw new OrbitException(OrbitError.Storage, "pending_activation");
                saved = credential ?? throw new OrbitException(OrbitError.ReauthenticationRequired);
                floating = sessionProfileKnown && sessionRequired;
            }
            if (floating) return await AdvanceSessionSerializedAsync(cancellationToken).ConfigureAwait(false);
            return await RequestGrantAsync($"/api/client/v1/activations/{saved.ActivationId}/validate",
                ValidationBody(saved), expected, saved, saved.LicenceId, cancellationToken, acquireSession).ConfigureAwait(false);
        }
        finally { serial.Release(); }
    }

    private async Task EnterSerialAsync(CancellationToken cancellationToken)
    {
        try { await serial.WaitAsync(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw new OrbitException(OrbitError.Cancelled); }
    }

    /// <summary>Checks current access and entitlement immediately before protected work, refreshing when needed.</summary>
    public async Task<Snapshot> RequireAccessAsync(string feature, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(feature);
        OrbitException.CheckCancellation(cancellationToken);
        Snapshot snapshot;
        bool retryDue;
        lock (gate)
        {
            snapshot = SnapshotLocked();
            OrbitException.CheckCancellation(cancellationToken);
            if (offlineFileMode)
            {
                if (snapshot.Access == Access.Expired)
                    throw new OrbitException(OrbitError.Denied, "offline_file_expired");
                if (!snapshot.HasFeature(feature))
                    throw new OrbitException(OrbitError.FeatureUnavailable, "feature_unavailable");
                return snapshot;
            }
            if (sessionRequired && sessionDisabled)
                throw new OrbitException(OrbitError.Denied, "session_explicitly_ended");
            if (snapshot.Access == Access.Online)
            {
                if (!snapshot.Entitlements.TryGetValue(feature, out var enabled) || !enabled)
                    throw new OrbitException(OrbitError.FeatureUnavailable, "feature_unavailable");
                return snapshot;
            }
            retryDue = RetryDueLocked();
        }
        if ((snapshot.Access is Access.RefreshRequired or Access.Expired or Access.Offline) && retryDue)
        {
            try { await RefreshIfDueAsync(cancellationToken).ConfigureAwait(false); }
            catch (OrbitException error) when (error.Error == OrbitError.Transient) { }
        }
        lock (gate)
        {
            OrbitException.CheckCancellation(cancellationToken);
            snapshot = SnapshotLocked();
            if (snapshot.Access is not (Access.Online or Access.Offline))
            {
                if (sessionRequired)
                {
                    if (transient) throw new OrbitException(OrbitError.Transient, "session_unavailable");
                    throw new OrbitException(OrbitError.Denied, "session_access_unavailable");
                }
                if (credential != null && transient)
                    throw new OrbitException(OrbitError.Transient);
                if (credential != null && versionDenial != null)
                    throw new OrbitException(OrbitError.AppVersionUnsupported, versionDenial.Code, versionDenial.RequestId);
                throw new OrbitException(OrbitError.NotActivated, "access_unavailable");
            }
            if (!snapshot.Entitlements.TryGetValue(feature, out var enabled) || !enabled)
                throw new OrbitException(OrbitError.FeatureUnavailable, "feature_unavailable");
            return snapshot;
        }
    }

    /// <summary>Prompts only when no usable activation exists; outages never trigger a prompt.</summary>
    public async Task<Snapshot> EnsureAccessAsync(string feature,
        Func<CancellationToken, ValueTask<string?>> askForKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(askForKey);
        try { return await RequireAccessAsync(feature, cancellationToken).ConfigureAwait(false); }
        catch (OrbitException error) when (error.Error == OrbitError.NotActivated)
        {
            var key = await askForKey(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(key))
                throw new OrbitException(OrbitError.NotActivated, "access_unavailable");
            await ActivateAsync(key, cancellationToken: cancellationToken).ConfigureAwait(false);
            return await RequireAccessAsync(feature, cancellationToken).ConfigureAwait(false);
        }
    }

    private bool RetryDueLocked()
    {
        try { return Clock.ElapsedTicks() >= nextRetryElapsedTicks; }
        catch (OrbitException) { return false; }
    }

    internal static long CreateRetryDeadline(long nowElapsedTicks)
    {
        var delaySeconds = RandomNumberGenerator.GetInt32(MinimumRetryDelaySeconds, MaximumRetryDelaySeconds + 1);
        return checked(nowElapsedTicks + delaySeconds * TimeSpan.TicksPerSecond);
    }

    private async Task<Snapshot> RefreshIfDueAsync(CancellationToken cancellationToken)
    {
        using var ownedOperation = InstallationOperation(cancellationToken);
        cancellationToken = ownedOperation?.Token ?? cancellationToken;
        await EnterSerialAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            StoredCredential saved;
            long expected;
            bool floating;
            lock (gate)
            {
                var snapshot = SnapshotLocked();
                OrbitException.CheckCancellation(cancellationToken);
                if (snapshot.OfflineFileMode)
                    return snapshot;
                if (!sessionRequired && (snapshot.Access is not (Access.RefreshRequired or Access.Expired or Access.Offline) || !RetryDueLocked()))
                    return snapshot;
                if (installed?.Record.PendingActivation != null)
                    throw new OrbitException(OrbitError.Storage, "pending_activation");
                saved = credential ?? throw new OrbitException(OrbitError.ReauthenticationRequired);
                expected = generation;
                floating = sessionProfileKnown && sessionRequired;
            }
            if (floating)
            {
                lock (gate)
                {
                    if (sessionDisabled || sessionRetryElapsedTicks > Clock.ElapsedTicks())
                        return SnapshotLocked();
                    if (sessionGrant != null && sessionAnchor != null &&
                        sessionAnchor.Now() < sessionGrant.RefreshAfter)
                        return SnapshotLocked();
                }
                return await AdvanceSessionSerializedAsync(cancellationToken).ConfigureAwait(false);
            }
            return await RequestGrantAsync($"/api/client/v1/activations/{saved.ActivationId}/validate",
                ValidationBody(saved), expected, saved, saved.LicenceId, cancellationToken).ConfigureAwait(false);
        }
        finally { serial.Release(); }
    }

    /// <summary>Clears access before returning the task. Await success to confirm the server released the device slot.</summary>
    public Task DeactivateAsync(string? idempotencyKey = null, CancellationToken cancellationToken = default)
    {
        if (idempotencyKey != null && !JsonWire.OperationId(idempotencyKey)) throw new OrbitException(OrbitError.Configuration);
        idempotencyKey ??= Device.NewInstallation().InstallationId;
        StoredCredential saved;
        long expected;
        lock (gate)
        {
            SyncStorage();
            CheckpointOfflineBeforeTransition();
            if (credential == null)
            {
                if (offlineFileMode)
                {
                    Clear(keepAccount: true);
                    InvalidateStorage();
                }
                throw new OrbitException(OrbitError.ReauthenticationRequired);
            }
            saved = credential;
            Clear(keepAccount: true);
            InvalidateStorage();
            expected = generation;
        }
        var body = CredentialBody(saved);
        body["idempotency_key"] = idempotencyKey;
        return FinishReleaseAsync($"/api/client/v1/activations/{saved.ActivationId}/deactivate", body, expected, cancellationToken);
    }

    private async Task FinishReleaseAsync(string path, Dictionary<string, object?> body, long expected,
        CancellationToken cancellationToken)
    {
        try
        {
            var response = await transport.PostAsync(path, body, true, cancellationToken).ConfigureAwait(false);
            lock (gate) { CheckGeneration(expected); OrbitException.CheckCancellation(cancellationToken); }
            if (response != null) throw JsonWire.Invalid();
        }
        catch (OrbitException)
        {
            lock (gate) CheckGeneration(expected);
            throw;
        }
    }

    private Dictionary<string, object?> ScopeBody() => new()
    {
        ["application_id"] = config.ApplicationId,
        ["environment_id"] = config.EnvironmentId
    };

    private Dictionary<string, object?> DeviceBody()
    {
        var body = ScopeBody();
        body["installation_id"] = device.InstallationId;
        body["fingerprint"] = device.Fingerprint;
        body["fingerprint_provider"] = device.FingerprintProvider;
        return body;
    }

    private Dictionary<string, object?> CredentialBody(StoredCredential saved)
    {
        var body = DeviceBody();
        body["credential"] = saved.Credential;
        return body;
    }

    private Dictionary<string, object?> ValidationBody(StoredCredential saved)
    {
        var body = CredentialBody(saved);
        if (appVersion != null) body["app_version"] = appVersion;
        return body;
    }

    private string ScopePath(string path, string? after = null) =>
        $"{path}?application_id={config.ApplicationId}&environment_id={config.EnvironmentId}" +
        (after == null ? "" : $"&after={after}");

    private async Task<Snapshot> RequestGrantAsync(string path, Dictionary<string, object?> body, long expected,
        StoredCredential? previous, string? expectedLicence, CancellationToken cancellationToken,
        bool allowSessionAcquisition = true)
    {
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        operation.CancelAfter(TimeSpan.FromSeconds(30));
        var verifyingReply = false;
        Snapshot? acceptedSnapshot = null;
        var acquireSession = false;
        try
        {
            var started = Clock.Capture();
            var response = await transport.PostAsync(path, body, true, operation.Token).ConfigureAwait(false);
            lock (gate) CheckGeneration(expected);
            verifyingReply = true;
            var hint = AppVersion.UpdateHint(response ?? throw JsonWire.Invalid());
            var verified = await VerifyReplyAsync(response ?? throw JsonWire.Invalid(), previous, expectedLicence, started, operation.Token)
                .ConfigureAwait(false);
            lock (gate)
            {
                CheckGeneration(expected);
                OrbitException.CheckCancellation(cancellationToken);
                if (operation.IsCancellationRequested)
                    throw new OrbitException(OrbitError.Transient);
                try
                {
                    if (installed != null && verified.SessionRequired)
                        installed.CommitFloating(storageVersion, verified.Credential, response!.Value);
                    else if (installed != null)
                        installed.Commit(storageVersion, verified.Credential, response!.Value, keys, verified.Anchor);
                    else
                        storage.Save(storageVersion, verified.Credential);
                }
                catch (Exception error)
                {
                    throw new OrbitException(error is OrbitException { Error: OrbitError.StaleResponse } ? OrbitError.StaleResponse : OrbitError.Storage);
                }
                credential = verified.Credential;
                claims = verified.Claims;
                anchor = verified.Anchor;
                var profileChanged = sessionRequired != verified.SessionRequired ||
                    sessionRequired && verified.SessionRequired &&
                    (sessionLicenceExpiry != verified.LicenceExpiry || sessionBindingMode != verified.BindingMode);
                if (!verified.SessionRequired || profileChanged)
                {
                    sessionGrant = null;
                    sessionAnchor = null;
                    pendingSessionId = null;
                    pendingRenewalSequence = null;
                    sessionRetryElapsedTicks = 0;
                    if (!verified.SessionRequired) sessionDisabled = false;
                }
                sessionRequired = verified.SessionRequired;
                sessionProfileKnown = true;
                sessionLicenceExpiry = verified.SessionRequired ? verified.LicenceExpiry : null;
                sessionBindingMode = verified.SessionRequired ? verified.BindingMode : null;
                transient = false;
                nextRetryElapsedTicks = 0;
                updateAvailable = hint;
                versionDenial = null;
                if (lifetime != null)
                {
                    lifetime.Restoring = false;
                    lifetime.Signal();
                }
                acceptedSnapshot = SnapshotLocked();
                acquireSession = allowSessionAcquisition && sessionRequired && !sessionDisabled;
            }
        }
        catch (OrbitException caught)
        {
            lock (gate)
            {
                CheckGeneration(expected);
                OrbitException.CheckCancellation(cancellationToken);
                var error = caught.Error == OrbitError.Cancelled && operation.IsCancellationRequested
                    ? new OrbitException(OrbitError.Transient) : caught;
                if (error.Error == OrbitError.Transient)
                {
                    if (verifyingReply)
                    {
                        // A reply that could not be verified cannot support online or offline access.
                        // Keep only the credential that was already stored for a later retry.
                        generation++;
                        claims = null;
                        installed?.DropCache();
                    }
                    var wasTransient = transient;
                    transient = true;
                    try { nextRetryElapsedTicks = CreateRetryDeadline(Clock.ElapsedTicks()); }
                    catch (OrbitException) { nextRetryElapsedTicks = long.MaxValue; }
                    catch (OverflowException) { nextRetryElapsedTicks = long.MaxValue; }
                    catch (CryptographicException) { nextRetryElapsedTicks = long.MaxValue; }
                    var snapshot = SnapshotLocked();
                    lifetime?.Signal();
                    if (snapshot.Access == Access.Offline)
                    {
                        if (lifetime != null && (!wasTransient || lifetime.Restoring))
                        {
                            lifetime.Restoring = false;
                            CheckpointInstalled(true);
                        }
                        return snapshot;
                    }
                }
                else if (error.Error == OrbitError.AppVersionUnsupported && previous != null)
                {
                    // Keep the activation for an updated application, but drop cached
                    // access without offline fallback and pace further validation.
                    generation++;
                    claims = null;
                    anchor = null;
                    transient = false;
                    sessionGrant = null;
                    sessionAnchor = null;
                    pendingSessionId = null;
                    pendingRenewalSequence = null;
                    updateAvailable = null;
                    versionDenial = error;
                    try { nextRetryElapsedTicks = CreateRetryDeadline(Clock.ElapsedTicks()); }
                    catch (OrbitException) { nextRetryElapsedTicks = long.MaxValue; }
                    catch (OverflowException) { nextRetryElapsedTicks = long.MaxValue; }
                    installed?.DropCache();
                }
                else if (error.Error != OrbitError.Cancelled)
                {
                    Clear();
                    if (installed != null && error.Error is not (OrbitError.Denied or OrbitError.AppVersionUnsupported))
                        storageVersion = installed.Invalidate(clearPending: false);
                    else
                        InvalidateStorage();
                }
                throw error;
            }
        }
        if (acceptedSnapshot != null)
            return acquireSession
                ? await StartSessionSerializedAsync(cancellationToken, explicitStart: false).ConfigureAwait(false)
                : acceptedSnapshot;
        throw JsonWire.Invalid();
    }

    private async Task<(StoredCredential Credential, GrantClaims? Claims, ClockAnchor Anchor,
        bool SessionRequired, long? LicenceExpiry, string BindingMode)> VerifyReplyAsync(
        JsonElement reply, StoredCredential? previous, string? expectedLicence, ClockStart started, CancellationToken cancellationToken)
    {
        if (JsonWire.Boolean(reply, "secret_replay_expired")) throw new OrbitException(OrbitError.ReauthenticationRequired);
        var activation = JsonWire.String(reply, "activation_id");
        var binding = JsonWire.String(reply, "binding_mode");
        if (!JsonWire.Opaque(activation) || JsonWire.String(reply, "installation_id") != device.InstallationId ||
            JsonWire.OptionalString(reply, "fingerprint_provider") != device.FingerprintProvider ||
            (device.Fingerprint == null ? binding != "none" : binding is not ("none" or "hwid"))) throw JsonWire.Invalid();
        var verifiedAnchor = new ClockAnchor(JsonWire.Timestamp(JsonWire.String(reply, "server_time")), started);
        var now = verifiedAnchor.Now();
        var expiryField = JsonWire.Field(reply, "credential_expires_at");
        long? expiry = expiryField.ValueKind == JsonValueKind.Null ? null : JsonWire.Timestamp(JsonWire.Text(expiryField));
        if (previous == null && (installed == null ? expiry == null : expiry != null))
            throw JsonWire.Invalid();
        var bearer = JsonWire.OptionalString(reply, "credential");
        if (expiry <= now || expiry > now + 30 * 86400 || (previous != null &&
            (activation != previous.ActivationId || expiry != (previous.CredentialExpiresAt == 0 ? null : (long?)previous.CredentialExpiresAt) || bearer != null)))
            throw JsonWire.Invalid();
        var licenceExpiry = JsonWire.OptionalString(reply, "licence_expires_at");
        bearer ??= previous?.Credential;
        if (bearer == null || !JsonWire.Bearer(bearer)) throw JsonWire.Invalid();
        var hasSessionFlag = reply.TryGetProperty("session_required", out var sessionField);
        if (hasSessionFlag && (sessionField.ValueKind != JsonValueKind.True)) throw JsonWire.Invalid();
        var requiresSession = hasSessionFlag;
        var grantField = JsonWire.Field(reply, "grant");
        if (requiresSession)
        {
            var sessionLicence = JsonWire.OptionalString(reply, "licence_id");
            if (grantField.ValueKind != JsonValueKind.Null || sessionLicence == null || !JsonWire.Opaque(sessionLicence) ||
                expectedLicence != null && sessionLicence != expectedLicence ||
                previous != null && sessionLicence != previous.LicenceId)
                throw JsonWire.Invalid();
            var savedSession = new StoredCredential
            {
                ApplicationId = config.ApplicationId,
                EnvironmentId = config.EnvironmentId,
                ActivationId = activation,
                LicenceId = sessionLicence,
                InstallationId = device.InstallationId,
                Credential = bearer,
                CredentialExpiresAt = expiry ?? 0,
                Fingerprint = device.Fingerprint,
                FingerprintProvider = device.FingerprintProvider
            };
            return (savedSession, null, verifiedAnchor, true,
                licenceExpiry == null ? null : JsonWire.Timestamp(licenceExpiry), binding);
        }
        var token = JsonWire.Text(grantField);
        if (!keys.Contains(token))
        {
            var jwks = await transport.GetAsync(ScopePath("/.well-known/orbit-jwks.json"), cancellationToken).ConfigureAwait(false);
            keys = GrantKeys.Parse(jwks ?? throw JsonWire.Invalid());
        }
        var verified = await keys.VerifyAsync(token, new GrantExpected(config, device, expectedLicence, activation, expiry,
            licenceExpiry == null ? null : JsonWire.Timestamp(licenceExpiry), verifiedAnchor.Now(),
            AllowUnboundFingerprint: true, ExpectedBindingMode: binding)).ConfigureAwait(false);
        var saved = new StoredCredential
        {
            ApplicationId = config.ApplicationId,
            EnvironmentId = config.EnvironmentId,
            ActivationId = activation,
            LicenceId = verified.LicenceId,
            InstallationId = device.InstallationId,
            Credential = bearer,
            CredentialExpiresAt = expiry ?? 0,
            Fingerprint = device.Fingerprint,
            FingerprintProvider = device.FingerprintProvider
        };
        return (saved, verified, verifiedAnchor, false,
            licenceExpiry == null ? null : JsonWire.Timestamp(licenceExpiry), binding);
    }
}
