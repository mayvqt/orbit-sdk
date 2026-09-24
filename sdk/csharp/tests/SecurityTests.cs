using Orbit.Sdk;
#if ORBIT_LOCAL_DEVELOPMENT
using System.Security.Cryptography;
using System.Text.Json;
#endif

internal static class SecurityTests
{
    internal static async Task<int> RunAsync()
    {
#if ORBIT_LOCAL_DEVELOPMENT
        (string Name, Func<CancellationToken, Task> Run)[] cases =
        [
            ("public setup connects with HTTPS and rejects invalid origin or scope", PublicSetupAsync),
            ("custom fingerprint providers match service grammar", FingerprintProvidersAsync),
            ("machine fingerprints preserve scoped framing and reject invalid identities", DeviceIdentityTests.RunAsync),
            ("protected storage codec binds scope and rejects malformed records", WindowsStorageTests.CodecAsync),
            ("Windows storage persists and exclusively leases protected credentials", WindowsStorageTests.NativeAsync),
            ("Secret Service framing and helper responses reject unsafe state", SecretServiceTests.CodecAsync),
            ("Linux storage lease rejects replaced and unsafe files without a keyring", SecretServiceTests.LeaseAsync),
            ("secret helper bounds private pipes and terminates failed children", SecretServiceTests.HelperAsync),
            ("clock rejects rollback and accounts for elapsed time", ClockAnchorsAsync),
            ("transient retry deadlines stay within randomized bounds", RetryDeadlineRangeAsync),
            ("delayed login cannot restore logged-out account", DelayedLoginAsync),
            ("delayed activation cannot restore logged-out access", DelayedActivationAsync),
            ("delayed validation cannot restore logged-out access", DelayedValidationAsync),
            ("delayed verification cannot restore logged-out access", DelayedVerificationAsync),
            ("transient verification cannot restore access after logout", TransientVerificationLogoutRaceAsync),
            ("delayed validation error cannot affect a new identity", DelayedValidationErrorAsync),
            ("delayed logout error cannot clear a new identity", DelayedLogoutErrorAsync),
            ("delayed deactivation error cannot clear a new identity", DelayedDeactivationErrorAsync),
            ("cancelled login cannot restore account", CancelledLoginAsync),
            ("cancelled activation cannot restore access", CancelledActivationAsync),
            ("cancelled verification cannot save access", CancelledVerificationAsync),
            ("cancelled validation preserves the original grant", CancelledValidationAsync),
            ("cancelled verification preserves the original grant", CancelledVerificationPreservesGrantAsync),
            ("cancelled queued operation sends nothing", CancelledQueuedOperationAsync),
            ("account logout clears before awaiting acknowledgement", LogoutBeforeAwaitAsync),
            ("cancelled account logout clears synchronously", CancelledLogoutAsync),
            ("shared storage invalidates account metadata", SharedStorageAsync),
            ("customer session proof is explicit redacted and locally invalidated", CustomerSessionProofAsync),
            ("HTTP errors retain only strict request references", ErrorRequestIdsAsync),
            ("support summaries are safe and independent of state", SupportSummaryAsync),
            ("HTTP transient metadata preserves offline policy", TransientMetadataAsync),
            ("shared storage invalidation rejects a pending grant", SharedStoragePendingGrantAsync),
            ("atomic storage invalidation rejects a stale save", StorageSaveRaceAsync),
            ("transient retries preserve request and operation", RetryIdentityAsync),
            ("unstructured gateway outages retry and recover", GatewayFailuresRetryAsync),
            ("initial activation never stores an unverified bearer", InitialActivationJwksOutageAsync),
            ("JWKS outage on saved credential retries without losing storage", SavedCredentialJwksRetryAsync),
            ("anchorless transient refreshes honor backoff and recover", AnchorlessTransientRefreshBackoffAsync),
            ("queued protected calls recheck transient refresh backoff", QueuedRefreshBackoffAsync),
            ("new-key JWKS outage revokes offline claims and keeps the credential", RotatedKeyJwksOutageAsync),
            ("malformed JWKS unknown key and invalid signature stay terminal", VerificationFailuresRemainTerminalAsync),
            ("transient retries stop at the attempt limit", RetryLimitAsync),
            ("Retry-After remains inside the operation budget", RetryBudgetAsync),
            ("cancellation stops transient retries", CancelRetryAsync),
            ("denied unknown and malformed errors never retry", NonRetryableErrorsAsync),
            ("non-idempotent account operations never retry", NonIdempotentOperationsAsync),
            ("only specified transient errors allow offline access", OfflineErrorClassificationAsync),
            ("malformed JSON fails closed", MalformedJsonAsync),
            ("malformed JOSE fails closed", MalformedJoseAsync),
            ("normal transport rejects HTTP", RejectHttpAsync),
            ("redirects never forward bearer bodies or headers", RedirectsAsync),
            ("pre-cancelled operations send nothing", CancelBeforeRequestAsync)
        ];
        var failures = 0;
        foreach (var test in cases)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            try { await test.Run(deadline.Token); }
            catch (Exception error)
            {
                failures++;
                // Avoid propagating third-party exception messages or request material.
                Console.Error.WriteLine($"FAIL: {test.Name} ({error.GetType().Name})");
            }
        }
        Console.WriteLine($"SDK security cases: {cases.Length - failures} passed, {failures} failed");
        return failures == 0 ? 0 : 1;
#else
        await Task.CompletedTask;
        Console.Error.WriteLine("Security fixtures require an explicit OrbitLocalDevelopment=true build");
        return 2;
#endif
    }

#if ORBIT_LOCAL_DEVELOPMENT
    private static Task PublicSetupAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using (var client = OrbitClient.Connect(new OrbitSetup(
            "https://orbit.example.test", "app", "test", "https://orbit.example.test", Installation)))
            Require(client.Snapshot().Access == Access.Denied);

        foreach (var setup in new[]
        {
            new OrbitSetup("http://orbit.example.test", "app", "test", "https://orbit.example.test", Installation),
            new OrbitSetup("https://orbit.example.test", "app", "invalid environment", "https://orbit.example.test", Installation)
        })
        {
            try { using var client = OrbitClient.Connect(setup); }
            catch (OrbitException error) when (error.Error == OrbitError.Configuration) { continue; }
            throw new InvalidOperationException("Invalid public setup accepted");
        }
        return Task.CompletedTask;
    }

    private static Task ClockAnchorsAsync(CancellationToken _)
    {
        var start = Clock.Capture();
        if (start.ElapsedTicks >= TimeSpan.TicksPerHour)
        {
            var elapsed = new ClockAnchor(1_800_000_000,
                new ClockStart(start.ElapsedTicks - TimeSpan.TicksPerHour, start.WallSeconds - 3600));
            Require(elapsed.Now() >= 1_800_003_600);
        }
        foreach (var invalid in new[]
        {
            new ClockStart(start.ElapsedTicks + TimeSpan.TicksPerHour, start.WallSeconds),
            new ClockStart(start.ElapsedTicks, start.WallSeconds + 60)
        })
        {
            try { new ClockAnchor(1_800_000_000, invalid).Now(); }
            catch (OrbitException error) when (error.Error == OrbitError.ClockUncertain) { continue; }
            throw new InvalidOperationException("Invalid clock anchor accepted");
        }
        return Task.CompletedTask;
    }

    private static Task RetryDeadlineRangeAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        const long now = 1_234_567_890;
        const long minimumTicks = 15 * TimeSpan.TicksPerSecond;
        const long maximumTicks = 44 * TimeSpan.TicksPerSecond;
        for (var sample = 0; sample < 128; sample++)
        {
            var delayTicks = OrbitClient.CreateRetryDeadline(now) - now;
            Require(delayTicks >= minimumTicks && delayTicks <= maximumTicks);
            Require(delayTicks % TimeSpan.TicksPerSecond == 0);
        }
        return Task.CompletedTask;
    }

    private const string Installation = "installation_1234";
    private static readonly string SessionToken = new('a', 43);
    private static readonly FixtureReply LoginReply = new(200, JsonSerializer.Serialize(new
    {
        customer = new
        {
            id = "customer", username = "alice", email = "alice@example.test", suspended = false,
            created_at = "2026-01-01T00:00:00Z"
        },
        session = SessionToken,
        expires_at = "2030-01-01T00:00:00Z"
    }));

    private static OrbitClient Client(Transport transport, ICredentialStorage? storage = null) =>
        new(new OrbitConfig("app", "test", "https://orbit.example.test"), new Device(Installation), transport, storage);

    private static TaskCompletionSource<T> Signal<T>() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static FixtureReply ErrorReply(int status, string code, string? retryAfter = null) =>
        new(status, JsonSerializer.Serialize(new { error = new { code, message = "Synthetic failure", request_id = "fixture" } }),
            RetryAfter: retryAfter);

    private sealed class GrantFixture : IDisposable
    {
        private readonly ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly long now;
        private readonly string keyId;
        internal FixtureReply Keys { get; }
        internal long Now => now;

        internal GrantFixture(string keyId = "fixture", long? now = null)
        {
            this.now = now ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            this.keyId = keyId;
            var key = signer.ExportParameters(false);
            Keys = new FixtureReply(200, JsonSerializer.Serialize(new { keys = new[] { new
            {
                kty = "EC", crv = "P-256", alg = "ES256", use = "sig", kid = keyId,
                x = JsonWire.EncodeBase64(key.Q.X!), y = JsonWire.EncodeBase64(key.Q.Y!)
            } } }));
        }

        internal FixtureReply Reply(bool validation = false, bool offlineAllowed = true)
        {
            var header = JsonWire.EncodeBase64(JsonSerializer.SerializeToUtf8Bytes(new { alg = "ES256", typ = "orbit-access+jwt", kid = keyId }));
            var payload = JsonWire.EncodeBase64(JsonSerializer.SerializeToUtf8Bytes(new
            {
                iss = "https://orbit.example.test", aud = "orbit:app:test", sub = "licence", jti = "fixture",
                application_id = "app", environment_id = "test", activation_id = "activation", installation_id = Installation,
                iat = now, nbf = now, exp = now + 300, refresh_after = now + 60,
                offline_allowed = offlineAllowed, policy_version = 1, entitlements = new { export = true },
                binding_mode = "none", fingerprint = (string?)null, fingerprint_provider = (string?)null,
                licence_expires_at = (long?)null
            }));
            var signed = header + "." + payload;
            var signature = signer.SignData(System.Text.Encoding.ASCII.GetBytes(signed), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return new FixtureReply(200, JsonSerializer.Serialize(new
            {
                activation_id = "activation", installation_id = Installation, credential = validation ? null : SessionToken,
                credential_expires_at = Timestamp(now + 86400), server_time = Timestamp(now),
                grant = signed + "." + JsonWire.EncodeBase64(signature), binding_mode = "none",
                fingerprint_provider = (string?)null, licence_expires_at = (string?)null, secret_replay_expired = false
            }));
        }

        private static string Timestamp(long value) => DateTimeOffset.FromUnixTimeSeconds(value)
            .ToString("yyyy-MM-ddTHH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

        public void Dispose() => signer.Dispose();
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Security assertion failed");
    }

    private static async Task ExpectAsync(OrbitError expected, Func<Task> operation)
    {
        try { await operation(); }
        catch (OrbitException error) when (error.Error == expected) { return; }
        throw new InvalidOperationException("Expected Orbit error was not returned");
    }

    private static Task FingerprintProvidersAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var transport = new Transport("https://orbit.example.test");
        var config = new OrbitConfig("app", "test", "https://orbit.example.test");
        foreach (var provider in new[] { "machine_v1", "custom:acme.v1", "custom:a-b_c.09", "custom:" + new string('a', 48) })
            _ = new OrbitClient(config, new Device(Installation, new string('a', 64), provider), transport);
        foreach (var provider in new[] { "", "custom:", "custom:UPPER", "custom:a/b", "custom:a b", "custom:é", "custom:" + new string('a', 49) })
        {
            try { _ = new OrbitClient(config, new Device(Installation, new string('a', 64), provider), transport); }
            catch (OrbitException error) when (error.Error == OrbitError.Configuration) { continue; }
            throw new InvalidOperationException("Invalid provider accepted");
        }
        return Task.CompletedTask;
    }

    private static async Task DelayedLoginAsync(CancellationToken cancellationToken)
    {
        var received = Signal<FixtureRequest>();
        var release = Signal<bool>();
        await using var server = new LoopbackServer(async (request, stopping) =>
        {
            received.SetResult(request);
            await release.Task.WaitAsync(stopping);
            return LoginReply;
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var client = Client(transport);
        var login = client.LoginAsync("alice", "synthetic password", cancellationToken);
        var request = await received.Task.WaitAsync(cancellationToken);
        Require(request.Method == "POST" && request.Path == "/api/client/v1/sessions");
        client.Logout();
        release.SetResult(true);
        await ExpectAsync(OrbitError.StaleResponse, () => login);
        Require(client.Account() == null && client.Snapshot().Access == Access.Denied);
    }

    private enum GrantStage { Activation, Validation, Verification }

    private static Task DelayedActivationAsync(CancellationToken token) => PendingGrantAsync(GrantStage.Activation, false, false, token);
    private static Task DelayedValidationAsync(CancellationToken token) => PendingGrantAsync(GrantStage.Validation, false, false, token);
    private static Task DelayedVerificationAsync(CancellationToken token) => PendingGrantAsync(GrantStage.Verification, false, false, token);
    private static Task CancelledActivationAsync(CancellationToken token) => PendingGrantAsync(GrantStage.Activation, true, false, token);
    private static Task CancelledValidationAsync(CancellationToken token) => PendingGrantAsync(GrantStage.Validation, true, false, token);
    private static Task CancelledVerificationAsync(CancellationToken token) => PendingGrantAsync(GrantStage.Verification, true, false, token);
    private static Task SharedStoragePendingGrantAsync(CancellationToken token) => PendingGrantAsync(GrantStage.Verification, false, true, token);

    private static async Task PendingGrantAsync(GrantStage stage, bool cancel, bool shared, CancellationToken cancellationToken)
    {
        using var fixture = new GrantFixture();
        var received = Signal<bool>();
        var release = Signal<bool>();
        var activationReply = fixture.Reply();
        var validationReply = fixture.Reply(validation: true);
        await using var server = new LoopbackServer(async (request, stopping) =>
        {
            var keys = request.Path.StartsWith("/.well-known/", StringComparison.Ordinal);
            var validation = request.Path.EndsWith("/validate", StringComparison.Ordinal);
            if (stage == GrantStage.Verification && keys || stage == GrantStage.Validation && validation ||
                stage == GrantStage.Activation && !keys)
            {
                received.SetResult(true);
                await release.Task.WaitAsync(stopping);
            }
            return keys ? fixture.Keys : validation ? validationReply : activationReply;
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var storage = new MemoryStorage();
        var client = Client(transport, storage);
        if (stage == GrantStage.Validation)
        {
            await client.ActivateAsync("synthetic-key", "operation_123456", cancellationToken);
            Require((await client.RequireAccessAsync("export", cancellationToken)).Access == Access.Online);
        }
        var original = storage.Load().Credential;
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var pending = stage == GrantStage.Validation ? client.RefreshAsync(operation.Token) :
            client.ActivateAsync("synthetic-key", "operation_123456", operation.Token);
        await received.Task.WaitAsync(cancellationToken);
        if (cancel) operation.Cancel();
        else if (shared) Client(transport, storage).Logout();
        else client.Logout();
        release.SetResult(true);
        await ExpectAsync(cancel ? OrbitError.Cancelled : OrbitError.StaleResponse, () => pending);
        Require(client.Account() == null);
        if (cancel && stage == GrantStage.Validation)
        {
            Require(client.Snapshot().Access == Access.Online && ReferenceEquals(storage.Load().Credential, original));
        }
        else Require(client.Snapshot().Access == Access.Denied && storage.Load().Credential == null);
    }

    private static async Task InitialActivationJwksOutageAsync(CancellationToken cancellationToken)
    {
        using var fixture = new GrantFixture();
        await using var server = new LoopbackServer((request, _) => Task.FromResult(
            request.Path.StartsWith("/.well-known/", StringComparison.Ordinal)
                ? ErrorReply(503, "service_unavailable") : fixture.Reply()));
        using var transport = Transport.LocalLoopback(server.Origin);
        var storage = new MemoryStorage();
        var client = Client(transport, storage);

        await ExpectAsync(OrbitError.Transient, () => client.ActivateAsync(
            "synthetic-key", "operation_123456", cancellationToken));
        Require(client.Snapshot().Access == Access.Denied);
        Require(client.Snapshot().Entitlements.Count == 0);
        Require(storage.Load().Credential == null && server.RequestCount == 4);
    }

    private static async Task SavedCredentialJwksRetryAsync(CancellationToken cancellationToken)
    {
        using var fixture = new GrantFixture();
        var keyRequests = 0;
        await using var server = new LoopbackServer((request, _) =>
        {
            if (request.Path.StartsWith("/.well-known/", StringComparison.Ordinal))
            {
                var attempt = Interlocked.Increment(ref keyRequests);
                return Task.FromResult(attempt is >= 2 and <= 4 ? ErrorReply(503, "service_unavailable") : fixture.Keys);
            }
            return Task.FromResult(request.Path.EndsWith("/validate", StringComparison.Ordinal)
                ? fixture.Reply(validation: true) : fixture.Reply());
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var storage = new MemoryStorage();
        var first = Client(transport, storage);
        await first.ActivateAsync("synthetic-key", "operation_123456", cancellationToken);
        var saved = storage.Load().Credential ?? throw new InvalidOperationException("Activation credential was not stored");

        var cold = Client(transport, storage);
        await ExpectAsync(OrbitError.Denied, () => cold.RequireAccessAsync("export", cancellationToken));
        Require(cold.Snapshot().Access == Access.RefreshRequired);
        RequireSameCredential(saved, storage.Load().Credential);

        Require((await cold.RefreshAsync(cancellationToken)).Access == Access.Online);
        Require((await cold.RequireAccessAsync("export", cancellationToken)).Access == Access.Online);
        RequireSameCredential(saved, storage.Load().Credential);
        Require(keyRequests == 5);
    }

    private static async Task AnchorlessTransientRefreshBackoffAsync(CancellationToken cancellationToken)
    {
        using var fixture = new GrantFixture();
        var validationRequests = 0;
        await using var server = new LoopbackServer((request, _) =>
        {
            if (request.Path.StartsWith("/.well-known/", StringComparison.Ordinal))
                return Task.FromResult(fixture.Keys);
            if (request.Path.EndsWith("/validate", StringComparison.Ordinal))
            {
                var attempt = Interlocked.Increment(ref validationRequests);
                return Task.FromResult(attempt == 1
                    ? ErrorReply(503, "service_unavailable", "30")
                    : fixture.Reply(validation: true));
            }
            return Task.FromResult(fixture.Reply());
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var storage = new MemoryStorage();
        var original = Client(transport, storage);
        await original.ActivateAsync("synthetic-key", "operation_123456", cancellationToken);
        var saved = storage.Load().Credential ?? throw new InvalidOperationException("Activation credential was not stored");

        var cold = Client(transport, storage);
        await ExpectAsync(OrbitError.Denied, () => cold.RequireAccessAsync("export", cancellationToken));
        Require(validationRequests == 1);
        Require(cold.Snapshot().Access == Access.RefreshRequired);
        RequireSameCredential(saved, storage.Load().Credential);

        await ExpectAsync(OrbitError.Denied, () => cold.RequireAccessAsync("export", cancellationToken));
        Require(validationRequests == 1);
        RequireSameCredential(saved, storage.Load().Credential);

        Require((await cold.RefreshAsync(cancellationToken)).Access == Access.Online);
        Require(validationRequests == 2);
        Require((await cold.RequireAccessAsync("export", cancellationToken)).Access == Access.Online);
        Require(validationRequests == 2);
    }

    private static async Task QueuedRefreshBackoffAsync(CancellationToken cancellationToken)
    {
        using var fixture = new GrantFixture();
        var received = Signal<bool>();
        var release = Signal<bool>();
        var validationRequests = 0;
        await using var server = new LoopbackServer(async (request, stopping) =>
        {
            if (request.Path.StartsWith("/.well-known/", StringComparison.Ordinal)) return fixture.Keys;
            if (request.Path.EndsWith("/validate", StringComparison.Ordinal))
            {
                var attempt = Interlocked.Increment(ref validationRequests);
                if (attempt == 1)
                {
                    received.TrySetResult(true);
                    await release.Task.WaitAsync(stopping);
                    return ErrorReply(503, "service_unavailable", "30");
                }
                return fixture.Reply(validation: true);
            }
            return fixture.Reply();
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var storage = new MemoryStorage();
        var original = Client(transport, storage);
        await original.ActivateAsync("synthetic-key", "operation_123456", cancellationToken);
        var saved = storage.Load().Credential ?? throw new InvalidOperationException("Activation credential was not stored");

        var cold = Client(transport, storage);
        var queuedCalls = Enumerable.Range(0, 8)
            .Select(_ => ExpectAsync(OrbitError.Denied, () => cold.RequireAccessAsync("export", cancellationToken)))
            .ToArray();
        await received.Task.WaitAsync(cancellationToken);
        release.SetResult(true);
        await Task.WhenAll(queuedCalls);

        Require(validationRequests == 1);
        Require(cold.Snapshot().Access == Access.RefreshRequired);
        RequireSameCredential(saved, storage.Load().Credential);
        Require((await cold.RefreshAsync(cancellationToken)).Access == Access.Online);
        Require(validationRequests == 2);
        Require((await cold.RequireAccessAsync("export", cancellationToken)).Access == Access.Online);
        Require(validationRequests == 2);
    }

    private static async Task RotatedKeyJwksOutageAsync(CancellationToken cancellationToken)
    {
        using var fixture = new GrantFixture();
        using var rotated = new GrantFixture("rotated", fixture.Now);
        var validationRequests = 0;
        var keyRequests = 0;
        await using var server = new LoopbackServer((request, _) =>
        {
            if (request.Path.StartsWith("/.well-known/", StringComparison.Ordinal))
            {
                var attempt = Interlocked.Increment(ref keyRequests);
                return Task.FromResult(attempt == 1 ? fixture.Keys : ErrorReply(503, "service_unavailable"));
            }
            if (request.Path.EndsWith("/validate", StringComparison.Ordinal))
            {
                var attempt = Interlocked.Increment(ref validationRequests);
                return Task.FromResult(attempt <= 3 ? ErrorReply(503, "service_unavailable") : rotated.Reply(validation: true));
            }
            return Task.FromResult(fixture.Reply());
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var storage = new MemoryStorage();
        var client = Client(transport, storage);
        await client.ActivateAsync("synthetic-key", "operation_123456", cancellationToken);
        var saved = storage.Load().Credential ?? throw new InvalidOperationException("Activation credential was not stored");

        Require((await client.RefreshAsync(cancellationToken)).Access == Access.Offline);
        Require((await client.RequireAccessAsync("export", cancellationToken)).Access == Access.Offline);
        await ExpectAsync(OrbitError.Transient, () => client.RefreshAsync(cancellationToken));

        Require(client.Snapshot().Access == Access.RefreshRequired);
        Require(client.Snapshot().Entitlements.Count == 0);
        RequireSameCredential(saved, storage.Load().Credential);
        await ExpectAsync(OrbitError.Denied, () => client.RequireAccessAsync("export", cancellationToken));
        RequireSameCredential(saved, storage.Load().Credential);
    }

    private enum VerificationFailure { MalformedJwks, UnknownKey, InvalidSignature }

    private static async Task VerificationFailuresRemainTerminalAsync(CancellationToken cancellationToken)
    {
        foreach (var failure in Enum.GetValues<VerificationFailure>())
        {
            using var fixture = new GrantFixture();
            using var rotated = new GrantFixture("rotated", fixture.Now);
            var validReply = fixture.Reply(validation: true);
            var validationReply = failure == VerificationFailure.InvalidSignature
                ? ReplaceGrant(validReply, MutateSignature(GrantFrom(validReply)))
                : rotated.Reply(validation: true);
            var keyRequests = 0;
            await using var server = new LoopbackServer((request, _) =>
            {
                if (request.Path.StartsWith("/.well-known/", StringComparison.Ordinal))
                {
                    var attempt = Interlocked.Increment(ref keyRequests);
                    if (attempt == 1) return Task.FromResult(fixture.Keys);
                    return Task.FromResult(failure switch
                    {
                        VerificationFailure.MalformedJwks => new FixtureReply(200, "{\"keys\":[]}"),
                        VerificationFailure.UnknownKey => fixture.Keys,
                        _ => fixture.Keys
                    });
                }
                return Task.FromResult(request.Path.EndsWith("/validate", StringComparison.Ordinal)
                    ? validationReply : fixture.Reply());
            });
            using var transport = Transport.LocalLoopback(server.Origin);
            var storage = new MemoryStorage();
            var client = Client(transport, storage);
            await client.ActivateAsync("synthetic-key", "operation_123456", cancellationToken);
            Require(storage.Load().Credential != null);

            await ExpectAsync(OrbitError.InvalidResponse, () => client.RefreshAsync(cancellationToken));
            Require(client.Snapshot().Access == Access.Denied && storage.Load().Credential == null);
        }
    }

    private static async Task CancelledVerificationPreservesGrantAsync(CancellationToken cancellationToken)
    {
        using var fixture = new GrantFixture();
        using var rotated = new GrantFixture("rotated", fixture.Now);
        var keyRequests = 0;
        var received = Signal<bool>();
        var release = Signal<bool>();
        await using var server = new LoopbackServer(async (request, stopping) =>
        {
            if (request.Path.StartsWith("/.well-known/", StringComparison.Ordinal))
            {
                var attempt = Interlocked.Increment(ref keyRequests);
                if (attempt == 1) return fixture.Keys;
                received.SetResult(true);
                await release.Task.WaitAsync(stopping);
                return rotated.Keys;
            }
            return request.Path.EndsWith("/validate", StringComparison.Ordinal)
                ? rotated.Reply(validation: true) : fixture.Reply();
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var storage = new MemoryStorage();
        var client = Client(transport, storage);
        await client.ActivateAsync("synthetic-key", "operation_123456", cancellationToken);
        var saved = storage.Load().Credential ?? throw new InvalidOperationException("Activation credential was not stored");
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var refresh = client.RefreshAsync(operation.Token);
        await received.Task.WaitAsync(cancellationToken);
        operation.Cancel();
        release.SetResult(true);

        await ExpectAsync(OrbitError.Cancelled, () => refresh);
        Require(client.Snapshot().Access == Access.Online);
        RequireSameCredential(saved, storage.Load().Credential);
    }

    private static async Task TransientVerificationLogoutRaceAsync(CancellationToken cancellationToken)
    {
        using var fixture = new GrantFixture();
        using var rotated = new GrantFixture("rotated", fixture.Now);
        var keyRequests = 0;
        var received = Signal<bool>();
        var release = Signal<bool>();
        await using var server = new LoopbackServer(async (request, stopping) =>
        {
            if (request.Path.StartsWith("/.well-known/", StringComparison.Ordinal))
            {
                var attempt = Interlocked.Increment(ref keyRequests);
                if (attempt == 1) return fixture.Keys;
                if (attempt == 2)
                {
                    received.SetResult(true);
                    await release.Task.WaitAsync(stopping);
                }
                return ErrorReply(503, "service_unavailable");
            }
            return request.Path.EndsWith("/validate", StringComparison.Ordinal)
                ? rotated.Reply(validation: true) : fixture.Reply();
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var storage = new MemoryStorage();
        var client = Client(transport, storage);
        await client.ActivateAsync("synthetic-key", "operation_123456", cancellationToken);
        var refresh = client.RefreshAsync(cancellationToken);
        await received.Task.WaitAsync(cancellationToken);
        client.Logout();
        release.SetResult(true);

        await ExpectAsync(OrbitError.StaleResponse, () => refresh);
        Require(client.Snapshot().Access == Access.Denied && storage.Load().Credential == null);
    }

    private static string GrantFrom(FixtureReply reply)
    {
        using var document = JsonDocument.Parse(reply.Body);
        return document.RootElement.GetProperty("grant").GetString() ?? throw new InvalidOperationException("Fixture grant is missing");
    }

    private static FixtureReply ReplaceGrant(FixtureReply reply, string grant)
    {
        var original = GrantFrom(reply);
        return reply with { Body = reply.Body.Replace(original, grant, StringComparison.Ordinal) };
    }

    private static string MutateSignature(string token)
    {
        var parts = token.Split('.');
        var signature = parts[2];
        parts[2] = (signature[0] == 'A' ? 'B' : 'A') + signature[1..];
        return string.Join('.', parts);
    }

    private static void RequireSameCredential(StoredCredential expected, StoredCredential? actual) =>
        Require(actual != null && actual.Credential == expected.Credential &&
            actual.ActivationId == expected.ActivationId && actual.LicenceId == expected.LicenceId &&
            actual.CredentialExpiresAt == expected.CredentialExpiresAt);

    private static async Task CancelledLoginAsync(CancellationToken cancellationToken)
    {
        var received = Signal<bool>();
        var release = Signal<bool>();
        await using var server = new LoopbackServer(async (_, stopping) =>
        {
            received.SetResult(true);
            await release.Task.WaitAsync(stopping);
            return LoginReply;
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var client = Client(transport);
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var pending = client.LoginAsync("alice", "synthetic password", operation.Token);
        await received.Task.WaitAsync(cancellationToken);
        operation.Cancel();
        release.SetResult(true);
        await ExpectAsync(OrbitError.Cancelled, () => pending);
        Require(client.Account() == null && client.Snapshot().Access == Access.Denied && server.RequestCount == 1);
    }

    private static async Task CancelledQueuedOperationAsync(CancellationToken cancellationToken)
    {
        var received = Signal<bool>();
        var release = Signal<bool>();
        await using var server = new LoopbackServer(async (_, stopping) =>
        {
            received.SetResult(true);
            await release.Task.WaitAsync(stopping);
            return LoginReply;
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var client = Client(transport);
        var first = client.LoginAsync("alice", "synthetic password", cancellationToken);
        await received.Task.WaitAsync(cancellationToken);
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var queued = client.LoginAsync("other", "synthetic password", operation.Token);
        operation.Cancel();
        await ExpectAsync(OrbitError.Cancelled, () => queued);
        release.SetResult(true);
        await first;
        Require(client.Account()?.Customer.Username == "alice" && server.RequestCount == 1);
    }

    private static async Task DelayedValidationErrorAsync(CancellationToken cancellationToken)
    {
        using var fixture = new GrantFixture();
        var received = Signal<bool>();
        var release = Signal<bool>();
        await using var server = new LoopbackServer(async (request, stopping) =>
        {
            if (request.Path.EndsWith("/validate", StringComparison.Ordinal))
            {
                received.SetResult(true);
                await release.Task.WaitAsync(stopping);
                return ErrorReply(403, "licence_revoked");
            }
            if (request.Path == "/api/client/v1/sessions") return LoginReply;
            return request.Path.StartsWith("/.well-known/", StringComparison.Ordinal) ? fixture.Keys : fixture.Reply();
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var client = Client(transport);
        await client.ActivateAsync("synthetic-key", "operation_123456", cancellationToken);
        var pending = client.RefreshAsync(cancellationToken);
        await received.Task.WaitAsync(cancellationToken);
        client.Logout();
        var login = client.LoginAsync("alice", "synthetic password", cancellationToken);
        release.SetResult(true);
        await ExpectAsync(OrbitError.StaleResponse, () => pending);
        await login;
        Require(client.Account()?.Customer.Username == "alice" && client.Snapshot().Access == Access.Denied);
    }

    private static Task DelayedLogoutErrorAsync(CancellationToken token) => DelayedReleaseErrorAsync(false, token);
    private static Task DelayedDeactivationErrorAsync(CancellationToken token) => DelayedReleaseErrorAsync(true, token);

    private static async Task DelayedReleaseErrorAsync(bool deactivate, CancellationToken cancellationToken)
    {
        using var fixture = new GrantFixture();
        var received = Signal<bool>();
        var release = Signal<bool>();
        await using var server = new LoopbackServer(async (request, stopping) =>
        {
            if (request.Method == "DELETE" || request.Path.EndsWith("/deactivate", StringComparison.Ordinal))
            {
                received.SetResult(true);
                await release.Task.WaitAsync(stopping);
                return ErrorReply(403, "licence_revoked");
            }
            if (request.Path == "/api/client/v1/sessions")
            {
                using var body = JsonDocument.Parse(request.Body);
                var username = body.RootElement.GetProperty("username").GetString();
                return LoginReply with { Body = LoginReply.Body.Replace("alice", username, StringComparison.Ordinal) };
            }
            return request.Path.StartsWith("/.well-known/", StringComparison.Ordinal) ? fixture.Keys : fixture.Reply();
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var client = Client(transport);
        await client.LoginAsync("alice", "synthetic password", cancellationToken);
        if (deactivate) await client.ActivateAccountAsync("licence", "operation_123456", cancellationToken);
        var pending = deactivate ? client.DeactivateAsync("operation_654321", cancellationToken) : client.LogoutAccountAsync(cancellationToken);
        await received.Task.WaitAsync(cancellationToken);
        await client.LoginAsync("bobby", "synthetic password", cancellationToken);
        release.SetResult(true);
        await ExpectAsync(OrbitError.StaleResponse, () => pending);
        Require(client.Account()?.Customer.Username == "bobby" && client.Snapshot().Access == Access.Denied);
    }

    private static async Task LogoutBeforeAwaitAsync(CancellationToken cancellationToken)
    {
        var received = Signal<FixtureRequest>();
        var release = Signal<bool>();
        await using var server = new LoopbackServer(async (request, stopping) =>
        {
            if (request.Method == "POST") return LoginReply;
            received.SetResult(request);
            await release.Task.WaitAsync(stopping);
            return new FixtureReply(204, "");
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var client = Client(transport);
        await client.LoginAsync("alice", "synthetic password", cancellationToken);
        Require(client.Account() != null);
        var logout = client.LogoutAccountAsync(cancellationToken);
        Require(client.Account() == null && client.Snapshot().Access == Access.Denied);
        var request = await received.Task.WaitAsync(cancellationToken);
        Require(request.Method == "DELETE" && request.Headers["Authorization"] == $"Bearer {SessionToken}");
        Require(!logout.IsCompleted);
        release.SetResult(true);
        await logout;
        Require(client.Account() == null && server.RequestCount == 2);
    }

    private static async Task CancelledLogoutAsync(CancellationToken cancellationToken)
    {
        await using var server = new LoopbackServer((_, _) => Task.FromResult(LoginReply));
        using var transport = Transport.LocalLoopback(server.Origin);
        var client = Client(transport);
        await client.LoginAsync("alice", "synthetic password", cancellationToken);
        Require(client.Account() != null);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        var logout = client.LogoutAccountAsync(cancelled.Token);
        Require(client.Account() == null && client.Snapshot().Access == Access.Denied);
        await ExpectAsync(OrbitError.Cancelled, () => logout);
        Require(server.RequestCount == 1);
    }

    private static async Task SharedStorageAsync(CancellationToken cancellationToken)
    {
        using var fixture = new GrantFixture();
        await using var server = new LoopbackServer((request, _) => Task.FromResult(
            request.Path == "/api/client/v1/sessions" ? LoginReply :
            request.Path.StartsWith("/.well-known/", StringComparison.Ordinal) ? fixture.Keys : fixture.Reply()));
        using var transport = Transport.LocalLoopback(server.Origin);
        var storage = new MemoryStorage();
        var first = Client(transport, storage);
        await first.LoginAsync("alice", "synthetic password", cancellationToken);
        await first.ActivateAccountAsync("licence", "operation_123456", cancellationToken);
        Require(first.Account() != null && first.Snapshot().Access == Access.Online);
        var second = Client(transport, storage);
        second.Logout();
        Require(first.Account() == null && first.Snapshot().Access == Access.Denied);
        Require(storage.Load().Credential == null && server.RequestCount == 3);
    }

    private sealed class CustomerSessionProofStorage : ICredentialStorage
    {
        private readonly MemoryStorage storage = new();
        private int writes;
        internal bool RejectAccess { get; set; }
        internal int Writes => Volatile.Read(ref writes);
        private void CheckAccess() { if (RejectAccess) throw new InvalidOperationException("Unexpected storage access"); }
        public StorageCapability Capability { get { CheckAccess(); return storage.Capability; } }
        public long Version { get { CheckAccess(); return storage.Version; } }
        public (long Version, StoredCredential? Credential) Load() { CheckAccess(); return storage.Load(); }
        public void Save(long version, StoredCredential credential)
        {
            CheckAccess();
            Interlocked.Increment(ref writes);
            storage.Save(version, credential);
        }
        public long Invalidate()
        {
            CheckAccess();
            Interlocked.Increment(ref writes);
            return storage.Invalidate();
        }
    }

    private static async Task CustomerSessionProofAsync(CancellationToken cancellationToken)
    {
        foreach (var sharedStorage in new[] { false, true })
        {
            await using var server = new LoopbackServer((request, _) =>
            {
                Require(request.Method == "POST" && request.Path == "/api/client/v1/sessions");
                return Task.FromResult(LoginReply);
            });
            using var transport = Transport.LocalLoopback(server.Origin);
            var storage = new CustomerSessionProofStorage();
            var client = Client(transport, storage);
            await ExpectAsync(OrbitError.ReauthenticationRequired, () => Task.FromResult(client.CustomerSessionProof()));
            Require(server.RequestCount == 0 && storage.Writes == 0);

            await client.LoginAsync("alice", "synthetic password", cancellationToken);
            var writes = storage.Writes;
            var proof = client.CustomerSessionProof();
            Require(proof.AuthorizationHeader() == "Bearer " + SessionToken);
            Require(proof.ToString() == "Orbit customer session proof (redacted)");
            Require($"{proof}" == "Orbit customer session proof (redacted)");
            Require(JsonSerializer.Serialize(proof) == "{}");
            var account = client.Account();
            Require(account != null);
            Require(!account!.ToString().Contains(SessionToken, StringComparison.Ordinal));
            Require(!JsonSerializer.Serialize(account).Contains(SessionToken, StringComparison.Ordinal));
            Require(server.RequestCount == 1 && storage.Writes == writes);

            if (sharedStorage) Client(transport, storage).Logout();
            else client.Logout();
            writes = storage.Writes;
            await ExpectAsync(OrbitError.ReauthenticationRequired, () => Task.FromResult(client.CustomerSessionProof()));
            Require(server.RequestCount == 1 && storage.Writes == writes);
            Require(client.Account() == null);
        }
    }

    private static async Task ErrorRequestIdsAsync(CancellationToken cancellationToken)
    {
        foreach (var (reference, valid) in new (object? Reference, bool Valid)[]
        {
            ("A-a_0", true), ("_", true), (new string('a', 64), true),
            ("", false), (new string('a', 65), false), ("a b", false), ("a/b", false),
            ("a\nb", false), ("é", false), (null, false), (123, false)
        })
        {
            foreach (var status in new[] { 403, 429, 503 })
            {
                var code = status == 403 ? "licence_expired" : status == 429 ? "rate_limited" : "service_unavailable";
                var reply = new FixtureReply(status, JsonSerializer.Serialize(new
                {
                    error = new { code, message = "synthetic-secret", request_id = reference }
                }));
                await using var server = new LoopbackServer((_, _) => Task.FromResult(reply));
                using var transport = Transport.LocalLoopback(server.Origin);
                OrbitException? failure = null;
                try { await transport.PostAsync("/api/client/v1/sessions", new Dictionary<string, object?>(), false, cancellationToken); }
                catch (OrbitException error) { failure = error; }
                var observed = failure ?? throw new InvalidOperationException("Missing HTTP failure");
                if (valid)
                {
                    Require(observed.Error == (status == 403 ? OrbitError.Denied : OrbitError.Transient));
                    Require(observed.Code == code && observed.RequestId == (string?)reference);
                }
                else Require(observed.Error == OrbitError.InvalidResponse && observed.RequestId == null);
                Require(!observed.ToString().Contains("synthetic-secret", StringComparison.Ordinal));
                Require(server.RequestCount == 1);
            }
        }
        var local = new OrbitException(OrbitError.Transient);
        Require(local.Code == null && local.RequestId == null);
    }

    private static async Task SupportSummaryAsync(CancellationToken cancellationToken)
    {
        await using var server = new LoopbackServer((_, _) => Task.FromResult(LoginReply));
        using var transport = Transport.LocalLoopback(server.Origin);
        var storage = new CustomerSessionProofStorage();
        var client = Client(transport, storage);
        await client.LoginAsync("alice", "synthetic password", cancellationToken);
        storage.RejectAccess = true;
        var summary = client.SupportSummary(new OrbitException(OrbitError.Denied, "licence_expired", "Req_A-9"));
        var encoded = JsonSerializer.Serialize(summary);
        using var json = JsonDocument.Parse(encoded);
        Require(json.RootElement.EnumerateObject().Count() == 5);
        Require(json.RootElement.GetProperty("application_id").GetString() == "app");
        Require(json.RootElement.GetProperty("environment_id").GetString() == "test");
        Require(json.RootElement.GetProperty("code").GetString() == "licence_expired");
        Require(json.RootElement.GetProperty("request_id").GetString() == "Req_A-9");
        Require(json.RootElement.GetProperty("timestamp").GetInt64() >= 0);
        Require(!encoded.Contains(SessionToken, StringComparison.Ordinal) && !encoded.Contains("alice", StringComparison.Ordinal));
        foreach (var error in new[]
        {
            new OrbitException(OrbitError.Denied, "synthetic-secret\n", "secret/token"),
            new OrbitException(OrbitError.Transient, new string('a', 129), new string('a', 65)),
            new OrbitException(OrbitError.Denied, "é", "é"),
            new OrbitException(OrbitError.Cancelled, "licence_expired", "reference"),
            new OrbitException(OrbitError.Transient)
        })
        {
            var safe = client.SupportSummary(error);
            Require(OrbitException.ValidCode(safe.Code) && safe.RequestId == null);
            Require(!JsonSerializer.Serialize(safe).Contains("synthetic-secret", StringComparison.Ordinal));
            Require(!error.ToString().Contains("synthetic-secret", StringComparison.Ordinal));
        }
        Require(client.SupportSummary(new OrbitException(OrbitError.Transient)).Code == "transient");
        foreach (var code in new[] { "future_error", new string('a', 128) })
        {
            var error = new OrbitException(OrbitError.Denied, code);
            Require(client.SupportSummary(error).Code == code);
            Require(error.Message == "Orbit denied access. Contact application support.");
        }
        foreach (var (code, guidance) in new[]
        {
            ("invalid_credentials", "Authenticate again with your licence key or customer account."),
            ("session_expired", "Sign in again to continue."),
            ("licence_expired", "Your licence has expired. Contact application support to renew it."),
            ("licence_suspended", "Your licence is suspended. Contact application support."),
            ("licence_revoked", "Your licence was revoked. Contact application support."),
            ("device_limit_reached", "The device limit is reached. Release an existing device or contact application support."),
            ("device_mismatch", "This device could not be verified. Contact application support."),
            ("reset_cooldown", "Device changes are temporarily limited. Wait before trying again."),
            ("application_maintenance", "The application is under maintenance. Try again after maintenance ends.")
        }) Require(new OrbitException(OrbitError.Denied, code, "reference").Message == guidance);
        Require(server.RequestCount == 1);
    }

    private static async Task TransientMetadataAsync(CancellationToken cancellationToken)
    {
        foreach (var offlineAllowed in new[] { false, true })
        {
            using var fixture = new GrantFixture();
            await using var server = new LoopbackServer((request, _) => Task.FromResult(
                request.Path.EndsWith("/validate", StringComparison.Ordinal) ? ErrorReply(503, "service_unavailable", "30") :
                request.Path.StartsWith("/.well-known/", StringComparison.Ordinal) ? fixture.Keys : fixture.Reply(offlineAllowed: offlineAllowed)));
            using var transport = Transport.LocalLoopback(server.Origin);
            var client = Client(transport);
            await client.ActivateAsync("synthetic-key", "operation_123456", cancellationToken);
            if (offlineAllowed) Require((await client.RefreshAsync(cancellationToken)).Access == Access.Offline);
            else
            {
                OrbitException? failure = null;
                try { await client.RefreshAsync(cancellationToken); }
                catch (OrbitException error) { failure = error; }
                Require(failure is { Error: OrbitError.Transient, Code: "service_unavailable", RequestId: "fixture" });
                Require(client.Snapshot().Access is not (Access.Online or Access.Offline));
            }
            Require(server.RequestCount == 3);
        }
    }

    private sealed class InvalidateOnSaveStorage : ICredentialStorage
    {
        private readonly MemoryStorage storage = new();
        public StorageCapability Capability => storage.Capability;
        public long Version => storage.Version;
        public (long Version, StoredCredential? Credential) Load() => storage.Load();
        public long Invalidate() => storage.Invalidate();
        public void Save(long version, StoredCredential credential)
        {
            storage.Invalidate();
            storage.Save(version, credential);
        }
    }

    private static async Task StorageSaveRaceAsync(CancellationToken cancellationToken)
    {
        using var fixture = new GrantFixture();
        await using var server = new LoopbackServer((request, _) => Task.FromResult(
            request.Path == "/api/client/v1/sessions" ? LoginReply :
            request.Path.StartsWith("/.well-known/", StringComparison.Ordinal) ? fixture.Keys : fixture.Reply()));
        using var transport = Transport.LocalLoopback(server.Origin);
        var storage = new InvalidateOnSaveStorage();
        var client = Client(transport, storage);
        await client.LoginAsync("alice", "synthetic password", cancellationToken);
        await ExpectAsync(OrbitError.StaleResponse, () => client.ActivateAccountAsync("licence", "operation_123456", cancellationToken));
        Require(client.Account() == null && client.Snapshot().Access == Access.Denied && storage.Load().Credential == null);
    }

    private static async Task RetryIdentityAsync(CancellationToken cancellationToken)
    {
        var requests = new List<FixtureRequest>();
        await using var server = new LoopbackServer((request, _) =>
        {
            requests.Add(request);
            return Task.FromResult(requests.Count < 3 ? ErrorReply(503, "service_unavailable") : new FixtureReply(200, "{}"));
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var reply = await transport.PostAsync("/api/client/v1/activations", new Dictionary<string, object?>
        {
            ["licence_key"] = "synthetic-key", ["idempotency_key"] = "operation_123456"
        }, true, cancellationToken);
        Require(reply != null && requests.Count == 3);
        Require(requests.All(request => request.Method == "POST" && request.Path == requests[0].Path && request.Body == requests[0].Body));
        using var body = JsonDocument.Parse(requests[0].Body);
        Require(body.RootElement.GetProperty("idempotency_key").GetString() == "operation_123456");
    }

    private static async Task GatewayFailuresRetryAsync(CancellationToken cancellationToken)
    {
        foreach (var (status, body) in new (int Status, string Body)[]
        {
            (502, "<html>Bad Gateway</html>"),
            (503, "Service Unavailable"),
            (504, "{\"message\":\"upstream timeout\"}")
        })
        {
            var attempts = 0;
            await using var server = new LoopbackServer((_, _) => Task.FromResult(
                ++attempts < 3 ? new FixtureReply(status, body) : new FixtureReply(200, "{}")));
            using var transport = Transport.LocalLoopback(server.Origin);
            var reply = await transport.GetAsync(
                "/.well-known/orbit-jwks.json?application_id=app&environment_id=test", cancellationToken);
            Require(reply.HasValue && reply.Value.ValueKind == JsonValueKind.Object && attempts == 3);
        }
    }

    private static async Task RetryLimitAsync(CancellationToken cancellationToken)
    {
        await using var server = new LoopbackServer((_, _) => Task.FromResult(ErrorReply(429, "rate_limited")));
        using var transport = Transport.LocalLoopback(server.Origin);
        await ExpectAsync(OrbitError.Transient, () => transport.GetAsync(
            "/.well-known/orbit-jwks.json?application_id=app&environment_id=test", cancellationToken));
        Require(server.RequestCount == 3);
    }

    private static async Task RetryBudgetAsync(CancellationToken cancellationToken)
    {
        await using var server = new LoopbackServer((_, _) => Task.FromResult(ErrorReply(503, "service_unavailable", "30")));
        using var transport = Transport.LocalLoopback(server.Origin);
        await ExpectAsync(OrbitError.Transient, () => transport.GetAsync(
            "/.well-known/orbit-jwks.json?application_id=app&environment_id=test", cancellationToken));
        Require(server.RequestCount == 1);
    }

    private static async Task CancelRetryAsync(CancellationToken cancellationToken)
    {
        var received = Signal<bool>();
        await using var server = new LoopbackServer((_, _) =>
        {
            received.TrySetResult(true);
            return Task.FromResult(ErrorReply(503, "service_unavailable", "5"));
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var pending = transport.GetAsync("/.well-known/orbit-jwks.json?application_id=app&environment_id=test", operation.Token);
        await received.Task.WaitAsync(cancellationToken);
        operation.Cancel();
        await ExpectAsync(OrbitError.Cancelled, () => pending);
        Require(server.RequestCount == 1);
    }

    private static async Task NonRetryableErrorsAsync(CancellationToken cancellationToken)
    {
        (FixtureReply Reply, OrbitError Error)[] responses =
        [
            (ErrorReply(401, "invalid_credentials"), OrbitError.Denied),
            (ErrorReply(403, "licence_revoked"), OrbitError.Denied),
            (ErrorReply(503, "invalid_credentials"), OrbitError.Denied),
            (ErrorReply(429, "licence_revoked"), OrbitError.Denied),
            (ErrorReply(503, "future_error"), OrbitError.Denied),
            (ErrorReply(429, "future_error"), OrbitError.Denied),
            (ErrorReply(500, "service_unavailable"), OrbitError.Denied),
            (ErrorReply(429, "service_unavailable"), OrbitError.Denied),
            (new FixtureReply(500, "{\"error\":"), OrbitError.InvalidResponse),
            (new FixtureReply(503, "{\"error\":null}"), OrbitError.InvalidResponse),
            (new FixtureReply(503, "{\"error\":{},\"error\":{}}"), OrbitError.InvalidResponse),
            (new FixtureReply(503, "{\"error\":{\"code\":\"service_unavailable\",\"message\":\"\",\"request_id\":\"fixture\"}}"), OrbitError.InvalidResponse)
        ];
        foreach (var response in responses)
        {
            await using var server = new LoopbackServer((_, _) => Task.FromResult(response.Reply));
            using var transport = Transport.LocalLoopback(server.Origin);
            await ExpectAsync(response.Error, () => transport.PostAsync("/api/client/v1/activations",
                new Dictionary<string, object?> { ["idempotency_key"] = "operation_123456" }, true, cancellationToken));
            Require(server.RequestCount == 1);
        }
    }

    private static async Task NonIdempotentOperationsAsync(CancellationToken cancellationToken)
    {
        string[] paths = ["/sessions", "/registrations", "/registrations/resend", "/password-recovery", "/email-changes"];
        foreach (var suffix in paths)
        {
            var attempts = 0;
            await using var server = new LoopbackServer((request, _) =>
            {
                if (request.Path == "/api/client/v1" + suffix)
                {
                    attempts++;
                    return Task.FromResult(ErrorReply(503, "service_unavailable"));
                }
                if (request.Path.EndsWith("/registrations", StringComparison.Ordinal))
                    return Task.FromResult(new FixtureReply(200, JsonSerializer.Serialize(new
                    {
                        accepted = true, expires_at = "2030-01-01T00:00:00Z", resend_credential = SessionToken
                    })));
                return Task.FromResult(LoginReply);
            });
            using var transport = Transport.LocalLoopback(server.Origin);
            var client = Client(transport);
            var registration = new Registration("synthetic-key", "alice", "alice@example.test", "synthetic password");
            if (suffix == "/email-changes") await client.LoginAsync("alice", "synthetic password", cancellationToken);
            var pending = suffix == "/registrations/resend" ? await client.RegisterAsync(registration, cancellationToken) : null;
            await ExpectAsync(OrbitError.Transient, () => suffix switch
            {
                "/sessions" => client.LoginAsync("alice", "synthetic password", cancellationToken),
                "/registrations" => client.RegisterAsync(registration, cancellationToken),
                "/registrations/resend" => client.ResendRegistrationAsync(pending!, cancellationToken),
                "/password-recovery" => client.RequestPasswordRecoveryAsync("alice@example.test", cancellationToken),
                _ => client.RequestEmailChangeAsync("synthetic password", "new@example.test", cancellationToken)
            });
            Require(attempts == 1 && client.Snapshot().Access == Access.Denied);
        }
    }

    private static async Task OfflineErrorClassificationAsync(CancellationToken cancellationToken)
    {
        foreach (var code in new[] { "service_unavailable", "future_error", "licence_revoked" })
        {
            using var fixture = new GrantFixture();
            await using var server = new LoopbackServer((request, _) => Task.FromResult(
                request.Path.EndsWith("/validate", StringComparison.Ordinal) ? ErrorReply(503, code, "30") :
                request.Path.StartsWith("/.well-known/", StringComparison.Ordinal) ? fixture.Keys : fixture.Reply()));
            using var transport = Transport.LocalLoopback(server.Origin);
            var storage = new MemoryStorage();
            var client = Client(transport, storage);
            await client.ActivateAsync("synthetic-key", "operation_123456", cancellationToken);
            if (code == "service_unavailable")
            {
                var offline = await client.RefreshAsync(cancellationToken);
                Require(offline.Access == Access.Offline && (await client.RequireAccessAsync("export", cancellationToken)).Access == Access.Offline);
            }
            else
            {
                await ExpectAsync(OrbitError.Denied, () => client.RefreshAsync(cancellationToken));
                Require(client.Snapshot().Access == Access.Denied && storage.Load().Credential == null);
            }
            Require(server.RequestCount == 3);
        }
    }

    private static async Task MalformedJsonAsync(CancellationToken cancellationToken)
    {
        await using var server = new LoopbackServer((_, _) => Task.FromResult(new FixtureReply(200, "{\"customer\":")));
        using var transport = Transport.LocalLoopback(server.Origin);
        var client = Client(transport);
        await ExpectAsync(OrbitError.InvalidResponse, () => client.LoginAsync("alice", "synthetic password", cancellationToken));
        Require(client.Account() == null && client.Snapshot().Access == Access.Denied && server.RequestCount == 1);
    }

    private static async Task MalformedJoseAsync(CancellationToken cancellationToken)
    {
        await using var server = new LoopbackServer((_, _) =>
        {
            var now = DateTimeOffset.UtcNow;
            return Task.FromResult(new FixtureReply(200, JsonSerializer.Serialize(new
            {
                activation_id = "activation", installation_id = Installation, credential = SessionToken,
                credential_expires_at = now.AddDays(30).ToString("yyyy-MM-ddTHH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture),
                grant = "e30.e30.AA",
                server_time = now.ToString("yyyy-MM-ddTHH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture),
                binding_mode = "none", fingerprint_provider = (string?)null, licence_expires_at = (string?)null,
                secret_replay_expired = false
            })));
        });
        using var transport = Transport.LocalLoopback(server.Origin);
        var client = Client(transport);
        await ExpectAsync(OrbitError.InvalidResponse, () => client.ActivateAsync("synthetic-key", "operation_123456", cancellationToken));
        Require(client.Snapshot().Access == Access.Denied && server.RequestCount == 1);
    }

    private static Task RejectHttpAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ExpectAsync(OrbitError.Configuration, () =>
        {
            using var transport = new Transport("http://127.0.0.1:8080");
            return Task.CompletedTask;
        });
    }

    private static async Task RedirectsAsync(CancellationToken cancellationToken)
    {
        await using var destination = new LoopbackServer((_, _) => Task.FromResult(new FixtureReply(200, "{}")));
        var requests = new List<FixtureRequest>();
        await using var source = new LoopbackServer((request, _) =>
        {
            requests.Add(request);
            return Task.FromResult(new FixtureReply(307, "{}", destination.Origin + request.Path));
        });
        using var transport = Transport.LocalLoopback(source.Origin);
        await ExpectAsync(OrbitError.InvalidResponse, () => transport.PostAsync("/api/client/v1/activations",
            new Dictionary<string, object?> { ["credential"] = SessionToken }, false, cancellationToken));
        await ExpectAsync(OrbitError.InvalidResponse, () => transport.GetAsync(
            "/api/client/v1/licences?application_id=app&environment_id=test", cancellationToken, SessionToken));
        Require(source.RequestCount == 2 && destination.RequestCount == 0);
        Require(requests[0].Body.Contains(SessionToken, StringComparison.Ordinal));
        Require(requests[1].Headers["Authorization"] == $"Bearer {SessionToken}");
    }

    private static async Task CancelBeforeRequestAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await using var server = new LoopbackServer((_, _) => Task.FromResult(LoginReply));
        using var transport = Transport.LocalLoopback(server.Origin);
        var client = Client(transport);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await ExpectAsync(OrbitError.Cancelled, () => client.LoginAsync("alice", "synthetic password", cancelled.Token));
        await ExpectAsync(OrbitError.Cancelled, () => transport.PostAsync("/api/client/v1/activations",
            new Dictionary<string, object?> { ["credential"] = SessionToken }, true, cancelled.Token));
        await ExpectAsync(OrbitError.Cancelled, () => transport.GetAsync(
            "/.well-known/orbit-jwks.json?application_id=app&environment_id=test", cancelled.Token));
        Require(server.RequestCount == 0 && client.Account() == null && client.Snapshot().Access == Access.Denied);
    }
#endif
}
