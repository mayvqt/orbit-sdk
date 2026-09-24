using System.Text.Json;

namespace Orbit.Sdk;

public sealed record Customer(string Id, string Username, string Email, bool Suspended, string CreatedAt);
public sealed record Account(Customer Customer, string ExpiresAt);
public sealed record OwnedLicence(string Id, string PolicyName, string State, string ExpiryMode,
    string? FirstUsedAt, string? ExpiresAt, long? DurationSeconds, int DeviceLimit, bool HwidLocked,
    bool OfflineAllowed, int OfflineSeconds, IReadOnlyDictionary<string, bool> Entitlements);
public sealed record OwnedLicences(IReadOnlyList<OwnedLicence> Items, string? NextCursor);

/// <summary>
/// Sensitive login proof held only in memory. Possession establishes neither
/// current session validity nor licensed access.
/// </summary>
public sealed class CustomerSessionProof
{
    private readonly string token;

    internal CustomerSessionProof(string token) { this.token = token; }

    /// <summary>
    /// Returns the sensitive Bearer authorization header value. Send it only to
    /// your own trusted HTTPS backend, which must verify the session online with
    /// Orbit. Never log or persist it, send it to arbitrary URLs, or forward it
    /// through redirects. This proof grants no licensed access.
    /// </summary>
    public string AuthorizationHeader() => "Bearer " + token;

    public override string ToString() => "Orbit customer session proof (redacted)";
}

/// <summary>Request input only. The client never retains passwords or raw licence keys.</summary>
public sealed class Registration(string licenceKey, string username, string email, string password)
{
    internal string LicenceKey { get; } = licenceKey;
    internal string Username { get; } = username;
    internal string Email { get; } = email;
    internal string Password { get; } = password;
    public override string ToString() => "Orbit registration (redacted)";
}

/// <summary>A scoped resend proof held only in memory. Not an account session or an access grant.</summary>
public sealed class PendingRegistration
{
    public bool Accepted => true;
    public string ExpiresAt { get; }
    internal string ResendCredential { get; }
    internal string ApplicationId { get; }
    internal string EnvironmentId { get; }
    internal PendingRegistration(string expiresAt, string resendCredential, OrbitConfig config)
    {
        ExpiresAt = expiresAt;
        ResendCredential = resendCredential;
        ApplicationId = config.ApplicationId;
        EnvironmentId = config.EnvironmentId;
    }
    public override string ToString() => "Orbit pending registration (redacted)";
}

internal sealed class CustomerSession(string token, Account account)
{
    internal string Token { get; } = token;
    internal Account Account { get; } = account;
}

public sealed partial class OrbitClient
{
    /// <summary>Local account metadata only; this grants no licensed access.</summary>
    public Account? Account()
    {
        lock (gate) { SyncStorage(); return session?.Account; }
    }

    /// <summary>
    /// Copies locally held login proof after synchronizing storage invalidation.
    /// This does not establish online validity or licensed access.
    /// </summary>
    public CustomerSessionProof CustomerSessionProof()
    {
        lock (gate)
        {
            SyncStorage();
            if (session == null) throw new OrbitException(OrbitError.ReauthenticationRequired);
            return new CustomerSessionProof(session.Token);
        }
    }

    public async Task<Account> LoginAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        if (username.Length is < 1 or > 128 || password.Length > 256) throw new OrbitException(OrbitError.Configuration);
        var expected = Generation();
        await EnterSerialAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            lock (gate)
            {
                CheckGeneration(expected);
                OrbitException.CheckCancellation(cancellationToken);
                Clear();
                InvalidateStorage();
                expected = generation;
            }
            try
            {
                var body = ScopeBody();
                body["username"] = username;
                body["password"] = password;
                var reply = await transport.PostAsync("/api/client/v1/sessions", body, false, cancellationToken).ConfigureAwait(false)
                    ?? throw JsonWire.Invalid();
                var customer = ReadCustomer(JsonWire.Field(reply, "customer"));
                var token = JsonWire.String(reply, "session");
                var expires = JsonWire.String(reply, "expires_at");
                _ = JsonWire.Timestamp(expires);
                if (!JsonWire.Bearer(token)) throw JsonWire.Invalid();
                var account = new Account(customer, expires);
                lock (gate)
                {
                    CheckGeneration(expected);
                    OrbitException.CheckCancellation(cancellationToken);
                    session = new CustomerSession(token, account);
                    return account;
                }
            }
            catch (OrbitException error) { throw FinishAccountError(error, expected, cancellationToken); }
        }
        finally { serial.Release(); }
    }

    public Task<Snapshot> ActivateAccountAsync(string licenceId, string idempotencyKey, CancellationToken cancellationToken = default) =>
        ActivateAccountWithPreviousAsync(licenceId, null, idempotencyKey, cancellationToken);

    public Task<Snapshot> ActivateAccountWithPreviousAsync(string licenceId, string? previousCredential, string idempotencyKey,
        CancellationToken cancellationToken = default) => ActivateAsAsync(licenceId, true, previousCredential, idempotencyKey, cancellationToken);

    /// <summary>Clears local state synchronously. Await the returned task to confirm remote session revocation.</summary>
    public Task LogoutAccountAsync(CancellationToken cancellationToken = default)
    {
        CustomerSession? saved;
        long expected;
        lock (gate)
        {
            SyncStorage();
            saved = session;
            Clear();
            InvalidateStorage();
            expected = generation;
        }
        return saved == null ? Task.CompletedTask : FinishLogoutAsync(saved, expected, cancellationToken);
    }

    private async Task FinishLogoutAsync(CustomerSession saved, long expected, CancellationToken cancellationToken)
    {
        try
        {
            var reply = await transport.DeleteAsync(ScopePath("/api/client/v1/sessions/current"), saved.Token, cancellationToken).ConfigureAwait(false);
            lock (gate) { CheckGeneration(expected); OrbitException.CheckCancellation(cancellationToken); }
            if (reply != null) throw JsonWire.Invalid();
        }
        catch (OrbitException)
        {
            lock (gate) CheckGeneration(expected);
            throw;
        }
    }

    public async Task<OwnedLicences> OwnedLicencesAsync(string? after = null, CancellationToken cancellationToken = default)
    {
        if (after != null && !JsonWire.Opaque(after)) throw new OrbitException(OrbitError.Configuration);
        var expected = Generation();
        await EnterSerialAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var current = GetSession(expected);
            try
            {
                var reply = await transport.GetAsync(ScopePath("/api/client/v1/licences", after), cancellationToken, current.Token).ConfigureAwait(false)
                    ?? throw JsonWire.Invalid();
                var entries = JsonWire.Field(reply, "items");
                if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() > 50) throw JsonWire.Invalid();
                var items = entries.EnumerateArray().Select(ReadLicence).ToArray();
                var cursor = JsonWire.OptionalString(reply, "next_cursor");
                if (cursor != null && !JsonWire.Opaque(cursor)) throw JsonWire.Invalid();
                return FinishAccount(new OwnedLicences(Array.AsReadOnly(items), cursor), expected, cancellationToken);
            }
            catch (OrbitException error) { throw FinishAccountError(error, expected, cancellationToken); }
        }
        finally { serial.Release(); }
    }

    public Task<OwnedLicence> ClaimLicenceAsync(string licenceKey, string idempotencyKey, CancellationToken cancellationToken = default)
    {
        if (licenceKey.Length is < 1 or > 256 || !JsonWire.OperationId(idempotencyKey)) throw new OrbitException(OrbitError.Configuration);
        var body = ScopeBody();
        body["licence_key"] = licenceKey;
        body["idempotency_key"] = idempotencyKey;
        return AccountPostAsync("/api/client/v1/licence-claims", body, true, ReadLicence, cancellationToken);
    }

    public async Task RequestEmailChangeAsync(string password, string email, CancellationToken cancellationToken = default)
    {
        if (password.Length > 256 || email.Length > 254) throw new OrbitException(OrbitError.Configuration);
        var body = ScopeBody();
        body["password"] = password;
        body["email"] = email;
        _ = await AccountPostAsync("/api/client/v1/email-changes", body, false, Accepted, cancellationToken).ConfigureAwait(false);
    }

    public async Task<PendingRegistration> RegisterAsync(Registration registration, CancellationToken cancellationToken = default)
    {
        if (registration.LicenceKey.Length is < 1 or > 256 || registration.Username.Length > 128 ||
            registration.Email.Length > 254 || registration.Password.Length > 256 ||
            registration.Password.EnumerateRunes().Count() < 8) throw new OrbitException(OrbitError.Configuration);
        var body = ScopeBody();
        body["licence_key"] = registration.LicenceKey;
        body["username"] = registration.Username;
        body["email"] = registration.Email;
        body["password"] = registration.Password;
        var reply = await transport.PostAsync("/api/client/v1/registrations", body, false, cancellationToken).ConfigureAwait(false)
            ?? throw JsonWire.Invalid();
        _ = Accepted(reply);
        var proof = JsonWire.String(reply, "resend_credential");
        var expiry = JsonWire.String(reply, "expires_at");
        _ = JsonWire.Timestamp(expiry);
        if (!JsonWire.Bearer(proof)) throw JsonWire.Invalid();
        return new PendingRegistration(expiry, proof, config);
    }

    public async Task ResendRegistrationAsync(PendingRegistration pending, CancellationToken cancellationToken = default)
    {
        if (pending.ApplicationId != config.ApplicationId || pending.EnvironmentId != config.EnvironmentId)
            throw new OrbitException(OrbitError.Configuration);
        var body = ScopeBody();
        body["resend_credential"] = pending.ResendCredential;
        _ = Accepted(await transport.PostAsync("/api/client/v1/registrations/resend", body, false, cancellationToken).ConfigureAwait(false)
            ?? throw JsonWire.Invalid());
    }

    public async Task RequestPasswordRecoveryAsync(string email, CancellationToken cancellationToken = default)
    {
        if (email.Length > 254) throw new OrbitException(OrbitError.Configuration);
        var body = ScopeBody();
        body["email"] = email;
        _ = Accepted(await transport.PostAsync("/api/client/v1/password-recovery", body, false, cancellationToken).ConfigureAwait(false)
            ?? throw JsonWire.Invalid());
    }

    private CustomerSession GetSession(long expected)
    {
        lock (gate)
        {
            CheckGeneration(expected);
            return session ?? throw new OrbitException(OrbitError.ReauthenticationRequired);
        }
    }

    private async Task<T> AccountPostAsync<T>(string path, Dictionary<string, object?> body, bool retrySafe,
        Func<JsonElement, T> decode, CancellationToken cancellationToken)
    {
        var expected = Generation();
        await EnterSerialAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            body["customer_session"] = GetSession(expected).Token;
            try
            {
                var response = await transport.PostAsync(path, body, retrySafe, cancellationToken).ConfigureAwait(false)
                    ?? throw JsonWire.Invalid();
                return FinishAccount(decode(response), expected, cancellationToken);
            }
            catch (OrbitException error) { throw FinishAccountError(error, expected, cancellationToken); }
        }
        finally { serial.Release(); }
    }

    private T FinishAccount<T>(T result, long expected, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            CheckGeneration(expected);
            OrbitException.CheckCancellation(cancellationToken);
            return result;
        }
    }

    private OrbitException FinishAccountError(OrbitException error, long expected, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            CheckGeneration(expected);
            OrbitException.CheckCancellation(cancellationToken);
            // Login-session expiry has a separate lifetime from activation access.
            if (error.Error is not (OrbitError.Transient or OrbitError.Cancelled) &&
                !(error.Error == OrbitError.Denied && error.Code == "session_expired"))
            {
                Clear();
                InvalidateStorage();
            }
            return error;
        }
    }

    private static bool Accepted(JsonElement reply) => JsonWire.Boolean(reply, "accepted") ? true : throw JsonWire.Invalid();

    private static Customer ReadCustomer(JsonElement value)
    {
        var customer = new Customer(JsonWire.String(value, "id"), JsonWire.String(value, "username"),
            JsonWire.String(value, "email"), JsonWire.Boolean(value, "suspended"), JsonWire.String(value, "created_at"));
        if (!JsonWire.Opaque(customer.Id) || customer.Suspended || customer.Username.Length is < 3 or > 32 ||
            !customer.Username.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_') || customer.Email.Length is < 1 or > 254)
            throw JsonWire.Invalid();
        _ = JsonWire.Timestamp(customer.CreatedAt);
        return customer;
    }

    private static OwnedLicence ReadLicence(JsonElement value)
    {
        var id = JsonWire.String(value, "id");
        var policy = JsonWire.String(value, "policy_name");
        var deviceLimit = JsonWire.Integer(value, "device_limit");
        var offlineSeconds = JsonWire.Integer(value, "offline_seconds");
        if (!JsonWire.Opaque(id) || policy.EnumerateRunes().Count() > 80 || deviceLimit is < 1 or > 100 || offlineSeconds is < 0 or > 86400)
            throw JsonWire.Invalid();
        var firstUsed = JsonWire.OptionalString(value, "first_used_at");
        var expires = JsonWire.OptionalString(value, "expires_at");
        if (firstUsed != null) _ = JsonWire.Timestamp(firstUsed);
        if (expires != null) _ = JsonWire.Timestamp(expires);
        return new OwnedLicence(id, policy, JsonWire.String(value, "state"), JsonWire.String(value, "expiry_mode"),
            firstUsed, expires, JsonWire.OptionalInteger(value, "duration_seconds"), (int)deviceLimit,
            JsonWire.Boolean(value, "hwid_locked"), JsonWire.Boolean(value, "offline_allowed"), (int)offlineSeconds,
            JsonWire.Entitlements(JsonWire.Field(value, "entitlements")));
    }
}
