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

    public StorageCapability StorageCapability { get; }

    public OrbitClient(OrbitConfig config, Device device, Transport transport, ICredentialStorage? storage = null)
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

    /// <summary>Creates a client from its public HTTPS origin and application scope.</summary>
    public static OrbitClient Connect(OrbitSetup setup)
    {
        ArgumentNullException.ThrowIfNull(setup);
        if (setup.ApiOrigin is null || setup.ApplicationId is null || setup.EnvironmentId is null ||
            setup.Issuer is null || setup.InstallationId is null)
            throw new OrbitException(OrbitError.Configuration);

        var config = new OrbitConfig(setup.ApplicationId, setup.EnvironmentId, setup.Issuer);
        var device = new Device(setup.InstallationId);
        config.Validate(device);

        var transport = new Transport(setup.ApiOrigin);
        try { return new OrbitClient(config, device, transport, null, true); }
        catch
        {
            transport.Dispose();
            throw;
        }
    }

    /// <summary>Releases an internally created transport. Injected transports remain caller-owned.</summary>
    public void Dispose()
    {
        if (ownsTransport && Interlocked.Exchange(ref disposed, 1) == 0) transport.Dispose();
    }

    public Snapshot Snapshot()
    {
        lock (gate) return SnapshotLocked();
    }

    private Snapshot SnapshotLocked()
    {
        SyncStorage();
        if (anchor != null)
        {
            try { _ = anchor.Now(); }
            catch (OrbitException)
            {
                // Keep the credential for online reconciliation; the old grant
                // and all responses started against its clock are superseded.
                claims = null;
                anchor = null;
                generation++;
            }
        }
        return SnapshotState();
    }

    private Snapshot SnapshotState()
    {
        var expiry = credential?.CredentialExpiresAt;
        var result = new Snapshot(credential == null ? Access.Denied : Access.RefreshRequired,
            global::Orbit.Sdk.Snapshot.EmptyEntitlements, null, null, expiry, credential == null, false, 0);
        if (claims == null || anchor == null) return result;
        long now;
        try { now = anchor.Now(); }
        catch (OrbitException) { return result; }
        var access = claims.ExpiresAt <= now ? Access.Expired : transient
            ? (claims.OfflineAllowed ? Access.Offline : Access.RefreshRequired)
            : claims.RefreshAfter <= now ? Access.RefreshRequired : Access.Online;
        var usable = access is Access.Online or Access.Offline;
        return new Snapshot(access, usable ? claims.Entitlements : global::Orbit.Sdk.Snapshot.EmptyEntitlements,
            claims.ExpiresAt, claims.RefreshAfter, expiry, expiry == null || expiry <= now + 86400,
            claims.OfflineAllowed, usable && claims.OfflineAllowed ? claims.ExpiresAt - now : 0)
        { PolicyVersion = claims.PolicyVersion };
    }

    private void SyncStorage()
    {
        long version;
        try { version = storage.Version; }
        catch (Exception)
        {
            Clear();
            throw new OrbitException(OrbitError.Storage);
        }
        if (version < 0) { Clear(); throw new OrbitException(OrbitError.Storage); }
        if (version != storageVersion) { Clear(); storageVersion = version; }
    }

    private void InvalidateStorage()
    {
        try { storageVersion = storage.Invalidate(); }
        catch (Exception) { Clear(); throw new OrbitException(OrbitError.Storage); }
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
        generation++;
        credential = null;
        claims = null;
        anchor = null;
        transient = false;
        nextRetryElapsedTicks = 0;
        if (!keepAccount) session = null;
    }

    /// <summary>Clear local access synchronously. This neither revokes the server session nor frees a device slot.</summary>
    public void Logout()
    {
        lock (gate) { Clear(); InvalidateStorage(); }
    }

    public Task<Snapshot> ActivateAsync(string licenceKey, string idempotencyKey,
        CancellationToken cancellationToken = default) => ActivateWithPreviousAsync(licenceKey, null, idempotencyKey, cancellationToken);

    public Task<Snapshot> ActivateWithPreviousAsync(string licenceKey, string? previousCredential, string idempotencyKey,
        CancellationToken cancellationToken = default) => ActivateAsAsync(licenceKey, false, previousCredential, idempotencyKey, cancellationToken);

    private async Task<Snapshot> ActivateAsAsync(string principal, bool account, string? previousCredential,
        string idempotencyKey, CancellationToken cancellationToken)
    {
        if ((account ? !JsonWire.Opaque(principal) : principal.Length is < 1 or > 256) ||
            !JsonWire.OperationId(idempotencyKey) || (previousCredential != null && !JsonWire.Bearer(previousCredential)))
            throw new OrbitException(OrbitError.Configuration);
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
                Clear(account);
                InvalidateStorage();
                expected = generation;
            }
            var body = DeviceBody();
            body["previous_credential"] = previousCredential;
            body["idempotency_key"] = idempotencyKey;
            if (account) { body["customer_session"] = customerSession; body["licence_id"] = principal; }
            else body["licence_key"] = principal;
            return await RequestGrantAsync("/api/client/v1/activations", body, expected, null,
                account ? principal : null, cancellationToken).ConfigureAwait(false);
        }
        finally { serial.Release(); }
    }

    public async Task<Snapshot> RefreshAsync(CancellationToken cancellationToken = default)
    {
        var expected = Generation();
        await EnterSerialAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            StoredCredential saved;
            lock (gate)
            {
                CheckGeneration(expected);
                OrbitException.CheckCancellation(cancellationToken);
                saved = credential ?? throw new OrbitException(OrbitError.ReauthenticationRequired);
            }
            return await RequestGrantAsync($"/api/client/v1/activations/{saved.ActivationId}/validate",
                CredentialBody(saved), expected, saved, saved.LicenceId, cancellationToken).ConfigureAwait(false);
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
        OrbitException.CheckCancellation(cancellationToken);
        var snapshot = Snapshot();
        bool retryDue;
        lock (gate)
        {
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
            SyncStorage();
            snapshot = SnapshotState();
            if (snapshot.Access is not (Access.Online or Access.Offline))
                throw new OrbitException(OrbitError.Denied, "access_unavailable");
            if (!snapshot.Entitlements.TryGetValue(feature, out var enabled) || !enabled)
                throw new OrbitException(OrbitError.Denied, "feature_unavailable");
            return snapshot;
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
        await EnterSerialAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            StoredCredential saved;
            long expected;
            lock (gate)
            {
                var snapshot = SnapshotLocked();
                OrbitException.CheckCancellation(cancellationToken);
                if (snapshot.Access is not (Access.RefreshRequired or Access.Expired or Access.Offline) || !RetryDueLocked())
                    return snapshot;
                saved = credential ?? throw new OrbitException(OrbitError.ReauthenticationRequired);
                expected = generation;
            }
            return await RequestGrantAsync($"/api/client/v1/activations/{saved.ActivationId}/validate",
                CredentialBody(saved), expected, saved, saved.LicenceId, cancellationToken).ConfigureAwait(false);
        }
        finally { serial.Release(); }
    }

    /// <summary>Clears access before returning the task. Await success to confirm the server released the device slot.</summary>
    public Task DeactivateAsync(string idempotencyKey, CancellationToken cancellationToken = default)
    {
        if (!JsonWire.OperationId(idempotencyKey)) throw new OrbitException(OrbitError.Configuration);
        StoredCredential saved;
        long expected;
        lock (gate)
        {
            SyncStorage();
            saved = credential ?? throw new OrbitException(OrbitError.ReauthenticationRequired);
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
        ["application_id"] = config.ApplicationId, ["environment_id"] = config.EnvironmentId
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

    private string ScopePath(string path, string? after = null) =>
        $"{path}?application_id={config.ApplicationId}&environment_id={config.EnvironmentId}" +
        (after == null ? "" : $"&after={after}");

    private async Task<Snapshot> RequestGrantAsync(string path, Dictionary<string, object?> body, long expected,
        StoredCredential? previous, string? expectedLicence, CancellationToken cancellationToken)
    {
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        operation.CancelAfter(TimeSpan.FromSeconds(30));
        var verifyingReply = false;
        try
        {
            var started = Clock.Capture();
            var response = await transport.PostAsync(path, body, true, operation.Token).ConfigureAwait(false);
            lock (gate) CheckGeneration(expected);
            verifyingReply = true;
            var verified = await VerifyReplyAsync(response ?? throw JsonWire.Invalid(), previous, expectedLicence, started, operation.Token)
                .ConfigureAwait(false);
            lock (gate)
            {
                CheckGeneration(expected);
                OrbitException.CheckCancellation(cancellationToken);
                if (operation.IsCancellationRequested) throw new OrbitException(OrbitError.Transient);
                try { storage.Save(storageVersion, verified.Credential); }
                catch (Exception error)
                {
                    throw new OrbitException(error is OrbitException { Error: OrbitError.StaleResponse } ? OrbitError.StaleResponse : OrbitError.Storage);
                }
                credential = verified.Credential;
                claims = verified.Claims;
                anchor = verified.Anchor;
                transient = false;
                nextRetryElapsedTicks = 0;
                return SnapshotState();
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
                    }
                    transient = true;
                    try { nextRetryElapsedTicks = CreateRetryDeadline(Clock.ElapsedTicks()); }
                    catch (OrbitException) { nextRetryElapsedTicks = long.MaxValue; }
                    catch (OverflowException) { nextRetryElapsedTicks = long.MaxValue; }
                    catch (CryptographicException) { nextRetryElapsedTicks = long.MaxValue; }
                    var snapshot = SnapshotState();
                    if (snapshot.Access == Access.Offline) return snapshot;
                }
                else if (error.Error != OrbitError.Cancelled)
                {
                    Clear();
                    InvalidateStorage();
                }
                throw error;
            }
        }
    }

    private async Task<(StoredCredential Credential, GrantClaims Claims, ClockAnchor Anchor)> VerifyReplyAsync(
        JsonElement reply, StoredCredential? previous, string? expectedLicence, ClockStart started, CancellationToken cancellationToken)
    {
        if (JsonWire.Boolean(reply, "secret_replay_expired")) throw new OrbitException(OrbitError.ReauthenticationRequired);
        var activation = JsonWire.String(reply, "activation_id");
        if (!JsonWire.Opaque(activation) || JsonWire.String(reply, "installation_id") != device.InstallationId ||
            JsonWire.OptionalString(reply, "fingerprint_provider") != device.FingerprintProvider ||
            JsonWire.String(reply, "binding_mode") != (device.Fingerprint == null ? "none" : "hwid")) throw JsonWire.Invalid();
        var verifiedAnchor = new ClockAnchor(JsonWire.Timestamp(JsonWire.String(reply, "server_time")), started);
        var now = verifiedAnchor.Now();
        var expiry = JsonWire.Timestamp(JsonWire.String(reply, "credential_expires_at"));
        var bearer = JsonWire.OptionalString(reply, "credential");
        if (expiry <= now || expiry > now + 30 * 86400 || (previous != null &&
            (activation != previous.ActivationId || expiry != previous.CredentialExpiresAt || bearer != null))) throw JsonWire.Invalid();
        var token = JsonWire.String(reply, "grant");
        if (!keys.Contains(token))
        {
            var jwks = await transport.GetAsync(ScopePath("/.well-known/orbit-jwks.json"), cancellationToken).ConfigureAwait(false);
            keys = GrantKeys.Parse(jwks ?? throw JsonWire.Invalid());
        }
        var licenceExpiry = JsonWire.OptionalString(reply, "licence_expires_at");
        var verified = await keys.VerifyAsync(token, new GrantExpected(config, device, expectedLicence, activation, expiry,
            licenceExpiry == null ? null : JsonWire.Timestamp(licenceExpiry), verifiedAnchor.Now())).ConfigureAwait(false);
        bearer ??= previous?.Credential;
        if (bearer == null || !JsonWire.Bearer(bearer)) throw JsonWire.Invalid();
        var saved = new StoredCredential
        {
            ApplicationId = config.ApplicationId, EnvironmentId = config.EnvironmentId,
            ActivationId = activation, LicenceId = verified.LicenceId, InstallationId = device.InstallationId,
            Credential = bearer, CredentialExpiresAt = expiry, Fingerprint = device.Fingerprint,
            FingerprintProvider = device.FingerprintProvider
        };
        return (saved, verified, verifiedAnchor);
    }
}
