using System.Text.Json;

namespace Orbit.Sdk;

public sealed partial class OrbitClient
{
    /// <summary>Acquire or reuse the current floating seat. Ordinary and offline access is unchanged.</summary>
    public async Task<Snapshot> StartSessionAsync(CancellationToken cancellationToken = default)
    {
        using var ownedOperation = InstallationOperation(cancellationToken);
        cancellationToken = ownedOperation?.Token ?? cancellationToken;
        bool known;
        lock (gate)
        {
            var current = SnapshotLocked();
            if (current.OfflineFileMode) return current;
            if (credential == null) throw new OrbitException(OrbitError.ReauthenticationRequired);
            sessionDisabled = false;
            known = sessionProfileKnown;
        }
        if (!known) await RefreshCoreAsync(cancellationToken, acquireSession: false).ConfigureAwait(false);
        await EnterSerialAsync(cancellationToken).ConfigureAwait(false);
        try { return await StartSessionSerializedAsync(cancellationToken, explicitStart: true).ConfigureAwait(false); }
        finally { serial.Release(); }
    }

    /// <summary>Clear local floating access and request seat release; ordinary and offline access is unchanged.</summary>
    public async Task<Snapshot> EndSessionAsync(CancellationToken cancellationToken = default)
    {
        using var ownedOperation = InstallationOperation(cancellationToken);
        cancellationToken = ownedOperation?.Token ?? cancellationToken;
        bool known;
        StoredCredential saved;
        string? sessionId;
        long expected;
        lock (gate)
        {
            var current = SnapshotLocked();
            if (current.OfflineFileMode || sessionProfileKnown && !sessionRequired)
                return current;
            OrbitException.CheckCancellation(cancellationToken);
            if (credential == null)
            {
                sessionDisabled = true;
                generation++;
                return current;
            }
            known = sessionProfileKnown;
            saved = credential;
            sessionDisabled = true;
            sessionId = sessionGrant?.SessionId ?? pendingSessionId;
            sessionGrant = null;
            sessionAnchor = null;
            pendingSessionId = null;
            pendingRenewalSequence = null;
            sessionRetryElapsedTicks = 0;
            generation++;
            expected = generation;
        }
        if (!known)
        {
            await RefreshCoreAsync(cancellationToken, acquireSession: false).ConfigureAwait(false);
            lock (gate) expected = generation;
        }
        await EnterSerialAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (gate)
            {
                CheckGeneration(expected);
                if (offlineFileMode || !sessionRequired) return SnapshotLocked();
            }
            if (sessionId != null)
            {
                var path = $"/api/client/v1/activations/{saved.ActivationId}/sessions/{sessionId}/end";
                var response = await transport.PostAsync(path, CredentialBody(saved), true, cancellationToken).ConfigureAwait(false);
                lock (gate)
                {
                    CheckGeneration(expected);
                    OrbitException.CheckCancellation(cancellationToken);
                }
                if (response != null) throw JsonWire.Invalid();
            }
            lock (gate) return SnapshotLocked();
        }
        finally { serial.Release(); }
    }

    private async Task<Snapshot> StartSessionSerializedAsync(CancellationToken cancellationToken, bool explicitStart)
    {
        StoredCredential saved;
        long expected;
        string sessionId;
        lock (gate)
        {
            SyncStorage();
            OrbitException.CheckCancellation(cancellationToken);
            if (offlineFileMode) return SnapshotLocked();
            if (!sessionRequired) return SnapshotLocked();
            if (sessionDisabled && !explicitStart)
                throw new OrbitException(OrbitError.Denied, "session_explicitly_ended");
            if (explicitStart) sessionDisabled = false;
            saved = credential ?? throw new OrbitException(OrbitError.ReauthenticationRequired);
            if (sessionGrant != null && sessionAnchor != null)
            {
                if (sessionAnchor.Now() < sessionGrant.ExpiresAt) return SnapshotLocked();
                sessionGrant = null;
                sessionAnchor = null;
                pendingRenewalSequence = null;
            }
            pendingSessionId ??= Device.NewInstallation().InstallationId;
            sessionId = pendingSessionId;
            expected = generation;
        }

        var route = $"/api/client/v1/activations/{saved.ActivationId}/sessions";
        var body = CredentialBody(saved);
        body["session_id"] = sessionId;
        var started = Clock.Capture();
        var sent = false;
        try
        {
            sent = true;
            var reply = await transport.PostAsync(route, body, true, cancellationToken).ConfigureAwait(false)
                ?? throw JsonWire.Invalid();
            var (grant, grantAnchor) = await VerifySessionReplyAsync(reply, sessionId, 1, saved, started, cancellationToken)
                .ConfigureAwait(false);
            lock (gate)
            {
                CheckGeneration(expected);
                OrbitException.CheckCancellation(cancellationToken);
                if (!sessionRequired || sessionDisabled || credential?.ActivationId != saved.ActivationId ||
                    pendingSessionId != sessionId)
                    throw new OrbitException(OrbitError.StaleResponse);
                sessionGrant = grant;
                sessionAnchor = grantAnchor;
                pendingSessionId = null;
                pendingRenewalSequence = null;
                sessionRetryElapsedTicks = 0;
                lifetime?.Signal();
                return SnapshotLocked();
            }
        }
        catch (OrbitException error)
        {
            if (sent && error.Error is OrbitError.Cancelled or OrbitError.StaleResponse)
            {
                lock (gate) if (pendingSessionId == sessionId) pendingSessionId = null;
                QueueSessionRelease(saved, sessionId);
            }
            else
            {
                lock (gate)
                {
                    if (generation != expected || !sessionRequired || credential?.ActivationId != saved.ActivationId ||
                        pendingSessionId != sessionId)
                        throw new OrbitException(OrbitError.StaleResponse);
                    if (error.Error == OrbitError.Transient ||
                        error.Error == OrbitError.Denied && error.Code == "concurrent_session_limit_reached")
                    {
                        try { sessionRetryElapsedTicks = CreateRetryDeadline(Clock.ElapsedTicks()); }
                        catch (OrbitException) { sessionRetryElapsedTicks = long.MaxValue; }
                        catch (OverflowException) { sessionRetryElapsedTicks = long.MaxValue; }
                        lifetime?.Signal();
                    }
                    else if (error.Error == OrbitError.Denied)
                    {
                        pendingSessionId = null;
                    }
                    else if (error.Error == OrbitError.InvalidResponse)
                    {
                        sessionGrant = null;
                        sessionAnchor = null;
                        pendingRenewalSequence = null;
                    }
                }
            }
            throw;
        }
    }

    private async Task<Snapshot> AdvanceSessionSerializedAsync(CancellationToken cancellationToken)
    {
        StoredCredential saved;
        SessionGrant? current = null;
        long expected = 0;
        long sequence = 0;
        bool startNew = false;
        lock (gate)
        {
            SyncStorage();
            OrbitException.CheckCancellation(cancellationToken);
            if (offlineFileMode || !sessionRequired || sessionDisabled) return SnapshotLocked();
            saved = credential ?? throw new OrbitException(OrbitError.ReauthenticationRequired);
            if (sessionRetryElapsedTicks > Clock.ElapsedTicks()) return SnapshotLocked();
            if (sessionGrant == null || sessionAnchor == null)
            {
                startNew = true;
            }
            else
            {
                current = sessionGrant;
                var now = sessionAnchor.Now();
                if (now >= current.ExpiresAt)
                {
                    sessionGrant = null;
                    sessionAnchor = null;
                    pendingRenewalSequence = null;
                    pendingSessionId = null;
                    current = null;
                    startNew = true;
                }
                else if (now < current.RefreshAfter) return SnapshotLocked();
                else
                {
                    if (pendingRenewalSequence == null)
                    {
                        if (current.Sequence >= 9007199254740991L)
                            throw new OrbitException(OrbitError.Denied, "session_sequence_exhausted");
                        pendingRenewalSequence = current.Sequence + 1;
                    }
                    sequence = pendingRenewalSequence.Value;
                    expected = generation;
                }
            }
        }
        if (startNew) return await StartSessionSerializedAsync(cancellationToken, explicitStart: false).ConfigureAwait(false);
        if (current == null) throw JsonWire.Invalid();

        var route = $"/api/client/v1/activations/{saved.ActivationId}/sessions/{current.SessionId}/renew";
        var body = CredentialBody(saved);
        body["sequence"] = sequence;
        var renewalStart = Clock.Capture();
        try
        {
            var reply = await transport.PostAsync(route, body, true, cancellationToken).ConfigureAwait(false)
                ?? throw JsonWire.Invalid();
            var (grant, grantAnchor) = await VerifySessionReplyAsync(reply, current.SessionId, sequence,
                saved, renewalStart, cancellationToken).ConfigureAwait(false);
            lock (gate)
            {
                CheckGeneration(expected);
                OrbitException.CheckCancellation(cancellationToken);
                if (sessionGrant?.SessionId != current.SessionId || sessionGrant.Sequence != current.Sequence ||
                    credential?.ActivationId != saved.ActivationId || sessionDisabled)
                    throw new OrbitException(OrbitError.StaleResponse);
                sessionGrant = grant;
                sessionAnchor = grantAnchor;
                pendingRenewalSequence = null;
                sessionRetryElapsedTicks = 0;
                lifetime?.Signal();
                return SnapshotLocked();
            }
        }
        catch (OrbitException error)
        {
            lock (gate)
            {
                if (generation != expected || credential?.ActivationId != saved.ActivationId ||
                    sessionGrant?.SessionId != current.SessionId || sessionGrant.Sequence != current.Sequence || sessionDisabled)
                    throw new OrbitException(OrbitError.StaleResponse);
                if (error.Error == OrbitError.Transient)
                {
                    try { sessionRetryElapsedTicks = CreateRetryDeadline(Clock.ElapsedTicks()); }
                    catch (OrbitException) { sessionRetryElapsedTicks = long.MaxValue; }
                    catch (OverflowException) { sessionRetryElapsedTicks = long.MaxValue; }
                    lifetime?.Signal();
                    var currentSnapshot = SnapshotLocked();
                    if (currentSnapshot.Access == Access.Online) return currentSnapshot;
                }
                else if (error.Error is OrbitError.Denied or OrbitError.InvalidResponse)
                {
                    sessionGrant = null;
                    sessionAnchor = null;
                    pendingRenewalSequence = null;
                }
            }
            throw;
        }
    }

    private async Task<(SessionGrant Grant, ClockAnchor Anchor)> VerifySessionReplyAsync(
        JsonElement reply, string sessionId, long sequence, StoredCredential saved,
        ClockStart started, CancellationToken cancellationToken)
    {
        JsonWire.ExactFields(reply, "session_id", "sequence", "expires_at", "server_time", "grant");
        if (JsonWire.String(reply, "session_id") != sessionId || JsonWire.Integer(reply, "sequence") != sequence ||
            !JsonWire.OperationId(sessionId)) throw JsonWire.Invalid();
        var expires = JsonWire.Timestamp(JsonWire.String(reply, "expires_at"));
        var clock = new ClockAnchor(JsonWire.Timestamp(JsonWire.String(reply, "server_time")), started);
        var token = JsonWire.String(reply, "grant");
        var trusted = sessionKeys;
        if (trusted == null || !trusted.Contains(token))
        {
            if (environmentName is not ("test" or "live")) throw new OrbitException(OrbitError.Configuration, "session_keys_required");
            var jwks = await transport.GetAsync(ScopePath("/.well-known/orbit-jwks.json"), cancellationToken)
                .ConfigureAwait(false) ?? throw JsonWire.Invalid();
            trusted = SessionKeys.Parse(jwks, environmentName);
            sessionKeys = trusted;
        }
        var expected = new GrantExpected(config, device, saved.LicenceId, saved.ActivationId,
            saved.CredentialExpiresAt == 0 ? null : saved.CredentialExpiresAt,
            sessionLicenceExpiry, clock.Now(), AllowUnboundFingerprint: true,
            ExpectedBindingMode: sessionBindingMode);
        var grant = trusted.Verify(token, new SessionExpected(expected, sessionId, sequence));
        if (grant.ExpiresAt != expires || grant.BindingMode != sessionBindingMode)
            throw JsonWire.Invalid();
        return (grant, clock);
    }

    private void QueueSessionRelease(StoredCredential saved, string sessionId)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await transport.PostAsync($"/api/client/v1/activations/{saved.ActivationId}/sessions/{sessionId}/end",
                    CredentialBody(saved), false, timeout.Token).ConfigureAwait(false);
            }
            catch { }
        });
    }
}
