using Orbit.Sdk;
#if ORBIT_LOCAL_DEVELOPMENT
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
#endif

internal static partial class InstalledTests
{
    internal static async Task<int> RunAsync()
    {
#if ORBIT_LOCAL_DEVELOPMENT
        (string Name, Func<Task> Run)[] cases =
        [
            ("persistent activation and online restart",OnlineRestart),
            ("app version is sent and an unsupported version denies without fallback", AppVersionPolicy),
            ("explicit online meters validate replay and uncertain IDs", OnlineOperations),
            ("updates select only the requested target", UpdateOperations),
            ("floating lifecycle acquires renews releases and restarts without cached session authority", FloatingLifecycle),
            ("floating denial clears authority while transient outage keeps only the signed interval", SessionFailures),
            ("ordinary and offline start and end are no-ops", SessionNoOps),
            ("blocked session replies cannot cross end logout close or cancellation", SessionFences),
            ("unknown floating profile end suppresses acquisition", UnknownSessionEnd),
            ("end fences an initial activation before credentials arrive", EndDuringInitialActivation),
            ("floating worker renews before expiry and bounds denial retries", SessionWorker),
            ("offline file import restart renewal expiry and retained sequence floor", OfflineFiles),
            ("offline time anchor survives account and online transitions", OfflineTransitionFloors),
            ("offline durable import fences cancellation and expiry", OfflineDurableFences),
            ("offline import queued behind activation is fenced by logout", OfflineStaleImport),
            ("original offline deadline survives qualified outage",OfflineRestart),
            ("strict restart outage does not request another key",StrictRestart),
            ("uncertain activation keeps identity after restart",PendingIdentity),
            ("failed account login preserves pending activation identity",PendingAccountIdentity),
            ("changed device identity rotates installation and clears old access",IdentityMismatch),
            ("pending mutation fences a retained credential",PendingFence),
            ("expired pending mutation requires deliberate resolution",PendingExpiry),
            ("malformed and incorrect expiry replies retain pending identity",MalformedIdentity),
            ("validation preserves finite or persistent mode and bearer",CredentialValidation),
            ("denial clears persisted authority",DeniedRestart),
            ("invalid cache clock and signature are durably discarded",InvalidCache),
            ("clock uncertainty at close durably discards cache",CloseClock),
            ("close cancels an active validation and releases ownership",CloseDuringRequest),
            ("format-2 rejects missing unknown and duplicate fields",Codec),
            ("lease contention missing data and unsafe leaf fail closed",Files),
            ("macOS renamed state directory is rejected before lease commit",MacOSDirectoryReplacement),
            ("interrupted writes and data links remain fenced",InterruptedFiles),
            ("abandoned clients release their installation lease",Abandoned),
            ("explicit previous bearer works without local credential",PreviousBearer),
            ("worker respects retry and access checks do not write",WorkerRetry)
        ];
        var failed = 0;
        foreach (var test in cases)
        {
            try
            {
                await test.Run().WaitAsync(TimeSpan.FromSeconds(20));
            }
            catch (OrbitException error)
            {
                failed++;
                Console.Error.WriteLine($"FAIL: {test.Name} ({error.Error}, {error.Code})");
            }
            catch (Exception error) { failed++; Console.Error.WriteLine($"FAIL: {test.Name} ({error.GetType().Name}: {error.Message})"); }
        }
        Console.WriteLine($"Installed client cases: {cases.Length - failed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;
#else
        await Task.CompletedTask;
        Console.Error.WriteLine("Installed fixtures require OrbitLocalDevelopment=true");
        return 2;
#endif
    }
    internal static async Task<int> RunBenchmarkAsync()
    {
#if ORBIT_LOCAL_DEVELOPMENT
        try
        {
            await using var fixture = new Fixture();
            await using var client = await fixture.Open();
            await fixture.Activate(client);
            for (var index = 0; index < 2_000; index++)
            {
                var guard = client.RequireAccessAsync("export").GetAwaiter().GetResult();
                var snapshot = client.Snapshot();
                Require(guard.Access == Access.Online && guard.HasFeature("export") &&
                    snapshot.Access == Access.Online && snapshot.HasFeature("export"));
            }

            var requests = fixture.Server.RequestCount;
            InstalledStorageDiagnostics.Begin();
            try
            {
                var guard = Measure(() => client.RequireAccessAsync("export").GetAwaiter().GetResult());
                var snapshot = Measure(client.Snapshot);
                Require(fixture.Server.RequestCount == requests);

                InstalledStorageDiagnostics.CountVersionReads(true);
                const int verificationCalls = 500;
                for (var index = 0; index < verificationCalls; index++)
                {
                    _ = client.RequireAccessAsync("export").GetAwaiter().GetResult();
                    _ = client.Snapshot();
                }
                var versionReads = InstalledStorageDiagnostics.VersionReads;
                Require(versionReads == verificationCalls * 2 &&
                    InstalledStorageDiagnostics.Writes == 0 && fixture.Server.RequestCount == requests);

#if DEBUG
                const string buildConfiguration = "Debug";
#else
                const string buildConfiguration = "Release";
#endif
                Console.WriteLine($"Access benchmark: OS={RuntimeInformation.OSDescription}; " +
                    $"arch={RuntimeInformation.ProcessArchitecture}; runtime={RuntimeInformation.FrameworkDescription}; " +
                    $"build={buildConfiguration}");
                Console.WriteLine($"RequireAccessAsync: median {guard.MicrosecondsPerOperation:F3} us/op, " +
                    $"{guard.BytesPerOperation:F1} allocated bytes/op (5 x 10000)");
                Console.WriteLine($"Snapshot: median {snapshot.MicrosecondsPerOperation:F3} us/op, " +
                    $"{snapshot.BytesPerOperation:F1} allocated bytes/op (5 x 10000)");
                Console.WriteLine($"Warm-loop checks: storage version reads={versionReads}; writes=0; " +
                    $"HTTP requests unchanged at {requests}");
            }
            finally { InstalledStorageDiagnostics.End(); }
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"Access benchmark failed: {error.GetType().Name}: {error.Message}");
            return 1;
        }
#else
        await Task.CompletedTask;
        Console.Error.WriteLine("Access benchmark requires OrbitLocalDevelopment=true");
        return 2;
#endif
    }
#if ORBIT_LOCAL_DEVELOPMENT
    private readonly record struct AccessMeasurement(double MicrosecondsPerOperation, double BytesPerOperation);

    private static AccessMeasurement Measure(Func<Snapshot> operation)
    {
        const int batchCount = 5;
        const int callsPerBatch = 10_000;
        var elapsed = new double[batchCount];
        var allocated = new double[batchCount];
        for (var batch = 0; batch < batchCount; batch++)
        {
            Snapshot? last = null;
            var startBytes = GC.GetAllocatedBytesForCurrentThread();
            var start = Stopwatch.GetTimestamp();
            for (var index = 0; index < callsPerBatch; index++) last = operation();
            elapsed[batch] = Stopwatch.GetElapsedTime(start).TotalMicroseconds / callsPerBatch;
            allocated[batch] = (GC.GetAllocatedBytesForCurrentThread() - startBytes) / (double)callsPerBatch;
            GC.KeepAlive(last);
        }
        Array.Sort(elapsed);
        Array.Sort(allocated);
        return new AccessMeasurement(elapsed[batchCount / 2], allocated[batchCount / 2]);
    }

    private static void Require(bool condition)
    {
        if (!condition)
            throw new InvalidOperationException("Installed client assertion failed");
    }
    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
    private static async Task Expect(OrbitError kind, Func<Task> run, string? code = null)
    {
        try
        {
            await run();
        }
        catch (OrbitException error) when (error.Error == kind && (code == null || error.Code == code)) { return; }
        throw new InvalidOperationException("Expected installed client failure");
    }
    private sealed class Fixture : IAsyncDisposable
    {
        internal readonly string Root = CreateRoot();
        private static string CreateRoot()
        {
            if (!OperatingSystem.IsMacOS()) return Directory.CreateTempSubdirectory("orbit-installed-").FullName;
            var cache = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Library", "Caches", "OrbitSdkTests");
            Directory.CreateDirectory(cache);
            var root = System.IO.Path.Combine(cache, "orbit-installed-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);
            return root;
        }
        internal string Path => System.IO.Path.Combine(Root, "state");
        internal readonly LoopbackServer Server;
        internal int Mode, Activations, Validations, SessionStarts, SessionRenewals, SessionEnds;
        internal bool Floating, FailFirstSessionStart, FailFirstSessionRenewal;
        internal bool DenySessionStart, DenySessionRenewal;
        internal int SessionRenewalFailures;
        internal TaskCompletionSource? SessionReceived, SessionRelease;
        internal long? ClockNow;
        internal readonly List<string> SessionIds = [];
        internal readonly List<long> RenewalSequences = [];
        private readonly Dictionary<string, long> sessionSequences = new(StringComparer.Ordinal);
        internal Func<FixtureRequest, FixtureReply?>? OnlineResponse;
        internal JsonNode? UpdateAvailable;
        internal bool LoginDenied;
        internal bool Offline = true;
        internal long? FiniteExpiry;
        internal readonly List<string> Operations = [];
        internal string? Previous;
        internal TaskCompletionSource? Received, Release;
        private readonly ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa offlineSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa sessionSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal OfflineKeys TrustedOfflineKeys { get; }
        internal SessionKeys TrustedSessionKeys { get; }
        internal string OfflineJwks { get; }
        internal Fixture()
        {
            Server = new LoopbackServer(Respond);
            var publicKey = offlineSigner.ExportParameters(false).Q;
            OfflineJwks = JsonSerializer.Serialize(new
            {
                keys = new[] { new { kty = "EC", crv = "P-256", alg = "ES256", use = "sig", kid = "offline-test-fixture",
                    x = JsonWire.EncodeBase64(publicKey.X!), y = JsonWire.EncodeBase64(publicKey.Y!) } }
            });
            TrustedOfflineKeys = OfflineKeys.Parse(OfflineJwks, "test");
            var sessionPublic = sessionSigner.ExportParameters(false).Q;
            var sessionJwks = JsonSerializer.Serialize(new
            {
                keys = new[] { new { kty = "EC", crv = "P-256", alg = "ES256", use = "sig", kid = "test-session-fixture",
                    x = JsonWire.EncodeBase64(sessionPublic.X!), y = JsonWire.EncodeBase64(sessionPublic.Y!) } }
            });
            TrustedSessionKeys = SessionKeys.Parse(sessionJwks, "test");
        }
        internal string Issuer => Server.Origin;
        internal InstalledScope Scope => new(Server.Origin, Issuer, "app", "test");
        internal string? CurrentFingerprint, CurrentProvider;
        internal Task<OrbitClient> Open(string? statePath = null, string? fingerprint = null,
            string? provider = null, bool disableMachineBinding = true, bool withOfflineKeys = true,
            string? appVersion = null)
        {
            var origin = JsonWire.EncodeBase64(Encoding.UTF8.GetBytes(Server.Origin));
            var appKey = $"orbit_app_test_{origin}.app.test";
            CurrentFingerprint = fingerprint;
            CurrentProvider = fingerprint == null ? null : provider;
            return OrbitClient.OpenLocalAsync(appKey, new OrbitOptions
            {
                StatePath = statePath ?? Path,
                DisableMachineBinding = disableMachineBinding,
                OfflineKeys = withOfflineKeys ? TrustedOfflineKeys : null,
                SessionKeys = TrustedSessionKeys,
                Fingerprint = fingerprint == null ? null : new Fingerprint(fingerprint, provider!),
                AppVersion = appVersion
            });
        }
        internal string SignOffline(string installation, long sequence, string issuance,
            long issued, long expires, bool export = true, bool reverseFields = false)
        {
            var header = JsonWire.EncodeBase64(JsonSerializer.SerializeToUtf8Bytes(new
            { alg = "ES256", typ = "orbit-offline+jwt", kid = "offline-test-fixture" }));
            var claims = new Dictionary<string, object?>
            {
                ["ver"] = 1, ["iss"] = Issuer, ["aud"] = "orbit-offline:app:test", ["sub"] = "licence",
                ["jti"] = issuance, ["iat"] = issued, ["nbf"] = issued, ["exp"] = expires,
                ["application_id"] = "app", ["environment_id"] = "test", ["activation_id"] = "activation",
                ["installation_id"] = installation, ["sequence"] = sequence, ["binding_mode"] = "none",
                ["policy_version"] = 1, ["entitlements"] = new Dictionary<string, bool> { ["export"] = export }
            };
            var ordered = reverseFields ? claims.Reverse().ToDictionary(item => item.Key, item => item.Value) : claims;
            var payload = JsonWire.EncodeBase64(JsonSerializer.SerializeToUtf8Bytes(ordered));
            var input = header + "." + payload;
            var signature = offlineSigner.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return input + "." + JsonWire.EncodeBase64(signature);
        }
        internal async Task Activate(OrbitClient client) => Require((await client.ActivateAsync("synthetic-key")).Access == Access.Online);
        private async Task<FixtureReply> Respond(FixtureRequest request, CancellationToken cancellationToken)
        {
            if (OnlineResponse?.Invoke(request) is { } online) return online;
            if (request.Method == "DELETE" && request.Path.StartsWith("/api/client/v1/sessions/current?", StringComparison.Ordinal))
                return new(204, string.Empty);
            if (request.Path.StartsWith("/.well-known/", StringComparison.Ordinal))
            {
                var key = signer.ExportParameters(false);
                return new(200, JsonSerializer.Serialize(new
                {
                    keys = new[] { new { kty = "EC", crv = "P-256", alg = "ES256", use = "sig", kid = "installed", x = JsonWire.EncodeBase64(key.Q.X!), y = JsonWire.EncodeBase64(key.Q.Y!) } }
                }));
            }
            if (request.Path.StartsWith("/api/client/v1/activations/activation/sessions", StringComparison.Ordinal))
            {
                var sessionBody = JsonNode.Parse(request.Body)!.AsObject();
                if (request.Path.EndsWith("/end", StringComparison.Ordinal))
                {
                    SessionEnds++;
                    return new(204, string.Empty);
                }
                var isStart = request.Path.EndsWith("/sessions", StringComparison.Ordinal);
                if (SessionReceived != null)
                {
                    SessionReceived.TrySetResult();
                    await SessionRelease!.Task.WaitAsync(cancellationToken);
                }
                var pathParts = request.Path.Split('/');
                var sessionId = isStart ? sessionBody["session_id"]!.GetValue<string>() : pathParts[^2];
                var sequence = isStart ? 1 : sessionBody["sequence"]!.GetValue<long>();
                if (isStart) SessionStarts++; else SessionRenewals++;
                if (isStart) SessionIds.Add(sessionId);
                else RenewalSequences.Add(sequence);
                if (isStart && DenySessionStart)
                    return new(409, "{\"error\":{\"code\":\"session_sequence_conflict\",\"message\":\"Stale session ID\",\"request_id\":\"fixture\"}}");
                if (!isStart && DenySessionRenewal)
                    return new(403, "{\"error\":{\"code\":\"session_ended\",\"message\":\"Session ended\",\"request_id\":\"fixture\"}}");
                if (!isStart && SessionRenewalFailures > 0)
                {
                    SessionRenewalFailures--;
                    return new(503, "{\"error\":{\"code\":\"service_unavailable\",\"message\":\"Unavailable\",\"request_id\":\"fixture\"}}");
                }
                if (isStart && FailFirstSessionStart)
                {
                    FailFirstSessionStart = false;
                    return new(503, "{\"error\":{\"code\":\"service_unavailable\",\"message\":\"Unavailable\",\"request_id\":\"fixture\"}}");
                }
                if (!isStart && FailFirstSessionRenewal)
                {
                    FailFirstSessionRenewal = false;
                    sessionSequences[sessionId] = sequence;
                    return new(503, "{\"error\":{\"code\":\"service_unavailable\",\"message\":\"Unavailable\",\"request_id\":\"fixture\"}}");
                }
                sessionSequences[sessionId] = sequence;
                var sessionNow = ClockNow ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var claims = new
                {
                    iss = Issuer, aud = "orbit-session:app:test", sub = "licence", jti = "session-token",
                    iat = sessionNow, nbf = sessionNow, exp = sessionNow + 120, application_id = "app", environment_id = "test",
                    activation_id = "activation", installation_id = sessionBody["installation_id"]!.GetValue<string>(),
                    binding_mode = "none", policy_version = 1, entitlements = new { export = true },
                    refresh_after = sessionNow + 60, offline_allowed = false, session_id = sessionId,
                    session_sequence = sequence
                };
                var sessionHeader = JsonWire.EncodeBase64(JsonSerializer.SerializeToUtf8Bytes(new
                    { alg = "ES256", typ = "orbit-session+jwt", kid = "test-session-fixture" }));
                var sessionPayload = JsonWire.EncodeBase64(JsonSerializer.SerializeToUtf8Bytes(claims));
                var signed = sessionHeader + "." + sessionPayload;
                var sessionSignature = sessionSigner.SignData(Encoding.ASCII.GetBytes(signed), HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                return new(200, JsonSerializer.Serialize(new
                {
                    session_id = sessionId, sequence, expires_at = DateTimeOffset.FromUnixTimeSeconds(sessionNow + 120).ToString("O"),
                    server_time = DateTimeOffset.FromUnixTimeSeconds(sessionNow).ToString("O"),
                    grant = signed + "." + JsonWire.EncodeBase64(sessionSignature)
                }));
            }
            if (request.Path == "/api/client/v1/sessions")
            {
                if (LoginDenied)
                    return new(403, "{\"error\":{\"code\":\"invalid_credentials\",\"message\":\"Invalid credentials\",\"request_id\":\"fixture\"}}");
                var accountTime = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                return new(200, JsonSerializer.Serialize(new
                {
                    customer = new
                    {
                        id = "customer_1", username = "alice", email = "alice@example.test",
                        suspended = false, created_at = accountTime.ToString("O")
                    },
                    session = new string('s', 43), expires_at = accountTime.AddDays(7).ToString("O")
                }));
            }
            var body = JsonNode.Parse(request.Body)!.AsObject();
            var activation = request.Path == "/api/client/v1/activations";
            if (activation)
            {
                Activations++;
                Operations.Add(body["idempotency_key"]!.GetValue<string>());
                Previous = body["previous_credential"]?.GetValue<string>();
                Require(body["credential_mode"]!.GetValue<string>() == "persistent");
            }
            else
                Validations++;
            if (Mode == 6)
            {
                Received!.TrySetResult();
                await Release!.Task.WaitAsync(cancellationToken);
            }
            if (Mode == 1)
                return new(503, "{\"error\":{\"code\":\"service_unavailable\",\"message\":\"Unavailable\",\"request_id\":\"fixture\"}}", RetryAfter: "30");
            if (Mode == 8)
                return new(403, "{\"error\":{\"code\":\"licence_suspended\",\"message\":\"Denied\",\"request_id\":\"fixture\"}}");
            if (Mode == 2)
                return new(403, "{\"error\":{\"code\":\"licence_revoked\",\"message\":\"Denied\",\"request_id\":\"fixture\"}}");
            if (Mode == 3)
                return new(200, "{\"malformed\":true}");
            var now = ClockNow ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var id = body["installation_id"]!.GetValue<string>();
            var header = JsonWire.EncodeBase64(JsonSerializer.SerializeToUtf8Bytes(new
            {
                alg = "ES256",
                typ = "orbit-access+jwt",
                kid = "installed"
            }));
            var payload = JsonWire.EncodeBase64(JsonSerializer.SerializeToUtf8Bytes(new
            {
                iss = Issuer,
                aud = "orbit:app:test",
                sub = "licence",
                jti = "grant",
                iat = now,
                nbf = now,
                exp = now + (Offline ? 3600 : 300),
                application_id = "app",
                environment_id = "test",
                activation_id = "activation",
                installation_id = id,
                binding_mode = "none",
                policy_version = 1,
                offline_allowed = Offline,
                refresh_after = now + (Offline && FiniteExpiry == null ? 900 : 60),
                licence_expires_at = (long?)null,
                entitlements = new
                {
                    export = true
                }
            }));
            var unsigned = header + "." + payload;
            var signature = signer.SignData(Encoding.ASCII.GetBytes(unsigned), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var response = JsonSerializer.SerializeToNode(new
            {
                activation_id = "activation",
                installation_id = id,
                credential = activation ? new string('c', 43) : null,
                credential_expires_at = FiniteExpiry is { } expiry ? DateTimeOffset.FromUnixTimeSeconds(expiry).ToString("O") : null,
                server_time = DateTimeOffset.FromUnixTimeSeconds(now).ToString("O"),
                grant = unsigned + "." + JsonWire.EncodeBase64(signature),
                binding_mode = "none",
                fingerprint_provider = CurrentProvider,
                licence_expires_at = (string?)null,
                secret_replay_expired = false
            })!.AsObject();
            if (Floating)
            {
                response["grant"] = null;
                response["session_required"] = true;
                response["licence_id"] = "licence";
            }
            if (Mode == 4)
                response.Remove("credential_expires_at");
            if (Mode == 5)
                response["credential_expires_at"] = DateTimeOffset.FromUnixTimeSeconds(now + 86400).ToString("O");
            if (Mode == 7)
                response["credential"] = new string('r', 43);
            if (UpdateAvailable != null)
                response["update_available"] = UpdateAvailable.DeepClone();
            return new(200, response.ToJsonString());
        }
        internal InstalledRecord Record(string? fingerprint = null, string? provider = null)
        {
            var bytes = File.ReadAllBytes(System.IO.Path.Combine(Path, "orbit-storage.bin"));
            if (OperatingSystem.IsWindows())
                bytes = WindowsDataProtection.UnprotectInstalled(bytes, SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(Scope, InstalledCodec.Options)));
            return InstalledCodec.Decode(bytes, Scope, OperatingSystem.IsWindows() ? "windows_dpapi" : "private_file", fingerprint, provider);
        }
        internal void WriteRecord(InstalledRecord record)
        {
            var entropy = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(Scope, InstalledCodec.Options));
            using IInstalledFiles files = OperatingSystem.IsWindows() ? new InstalledWindowsFiles(Path, entropy) : new InstalledLinuxFiles(Path);
            _ = files.Read();
            files.Write(InstalledCodec.Encode(record));
        }
        public async ValueTask DisposeAsync()
        {
            Release?.TrySetResult();
            await Server.DisposeAsync();
            signer.Dispose();
            offlineSigner.Dispose();
            sessionSigner.Dispose();
            Directory.Delete(Root, true);
        }
    }
    private static async Task FloatingLifecycle()
    {
        var wall = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var elapsed = TimeSpan.TicksPerSecond * 10;
        Clock.SetTestClock(() => new ClockStart(elapsed, wall));
        try
        {
            await using var f = new Fixture { Floating = true, FailFirstSessionStart = true, ClockNow = wall };
            var client = await f.Open();
            var first = await client.ActivateAsync("synthetic-key");
            Require(first.Access == Access.Online && first.Session is { Sequence: 1 });
            var saved = f.Record();
            Require(saved.Credential != null && saved.Access == null,
                "activation credential must be durable before the floating seat is acquired");
            var originalId = first.Session!.Id;
            Require(f.SessionStarts == 2 && f.SessionIds.Count >= 2 &&
                f.SessionIds[0] == originalId && f.SessionIds[1] == originalId,
                "uncertain start retry must reuse the same session ID");
            var reused = await client.StartSessionAsync();
            Require(reused.Session?.Id == originalId && f.SessionStarts == 2,
                "start_session must reuse a still-valid seat");

            elapsed += 61 * TimeSpan.TicksPerSecond;
            wall += 61;
            f.ClockNow = wall;
            f.FailFirstSessionRenewal = true;
            var renewed = await client.RefreshAsync();
            Require(renewed.Session is { Sequence: 2 } && f.SessionRenewals == 2 &&
                f.RenewalSequences[0] == 2 && f.RenewalSequences[1] == 2,
                "uncertain renewal must retry one sequence and advance only after acceptance");
            Require(f.Record().Access == null, "session grants must never enter the persistent access cache");

            var ended = await client.EndSessionAsync();
            Require(ended.Session == null && f.SessionEnds == 1,
                "end_session must remove local authority and release the current seat");
            await Expect(OrbitError.Denied, () => client.RequireAccessAsync("export"), "session_explicitly_ended");
            Require(f.SessionStarts == 2, "guards must not reacquire after explicit end");
            var resumed = await client.StartSessionAsync();
            Require(resumed.Session is { Sequence: 1 } && resumed.Session.Id != originalId && f.SessionStarts == 3,
                "explicit start must use a fresh ID after release");
            await client.DisposeAsync();

            var restarted = await f.Open();
            var postRestart = restarted.Snapshot();
            Require(postRestart.Session is { Sequence: 1 } && postRestart.Session.Id != resumed.Session!.Id &&
                f.Record().Access == null,
                "restart must validate the stored credential and acquire a fresh, nonrestored session");
            await restarted.DisposeAsync();
        }
        finally { Clock.SetTestClock(null); }
    }

    private static async Task SessionFailures()
    {
        var wall = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var elapsed = 10 * TimeSpan.TicksPerSecond;
        Clock.SetTestClock(() => new ClockStart(elapsed, wall));
        try
        {
            await using (var f = new Fixture { Floating = true, ClockNow = wall })
            await using (var client = await f.Open())
            {
                var initial = await client.ActivateAsync("synthetic-key");
                var id = initial.Session!.Id;
                elapsed += 61 * TimeSpan.TicksPerSecond;
                wall += 61;
                f.ClockNow = wall;
                f.SessionRenewalFailures = 3;
                var outage = await client.RefreshAsync();
                Require(outage.Access == Access.Online && outage.Session?.Id == id && outage.Session.Sequence == 1 &&
                    f.SessionRenewals == 3,
                    "a transient renewal outage must preserve only the exact still-valid signed session interval");

                f.DenySessionStart = true;
                elapsed += 59 * TimeSpan.TicksPerSecond;
                wall += 59;
                f.ClockNow = wall;
                f.DenySessionStart = true;
                Require(client.Snapshot().Access != Access.Online,
                    "the signed session must be expired at its exact deadline after an outage");
                await Expect(OrbitError.Denied, () => client.RequireAccessAsync("export"));
                Require(client.Snapshot().Session == null && client.Snapshot().Access != Access.Online,
                    "a final warm guard must not return access after the signed deadline");
                await Expect(OrbitError.Denied, () => client.StartSessionAsync(), "session_sequence_conflict");
                var firstDeadId = f.SessionIds[^1];
                await Expect(OrbitError.Denied, () => client.StartSessionAsync(), "session_sequence_conflict");
                Require(f.SessionIds[^1] != firstDeadId,
                    "an authoritative dead-ID conflict must generate a new start ID for a later explicit retry");
            }

            wall = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            elapsed = 20 * TimeSpan.TicksPerSecond;
            await using (var f = new Fixture { Floating = true, ClockNow = wall, DenySessionRenewal = true })
            await using (var client = await f.Open())
            {
                await client.ActivateAsync("synthetic-key");
                elapsed += 61 * TimeSpan.TicksPerSecond;
                wall += 61;
                f.ClockNow = wall;
                f.DenySessionStart = true;
                try { await client.RefreshAsync(); }
                catch (OrbitException error) when (error.Error == OrbitError.Denied) { }
                Require(client.Snapshot().Session == null && client.Snapshot().Access != Access.Online,
                    "an authoritative renewal denial must clear the current access grant");
                await Expect(OrbitError.Denied, () => client.RequireAccessAsync("export"));
            }
        }
        finally { Clock.SetTestClock(null); }
    }

    private static async Task SessionWorker()
    {
        var wall = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var elapsed = 10 * TimeSpan.TicksPerSecond;
        Clock.SetTestClock(() => new ClockStart(elapsed, wall));
        try
        {
            await using var f = new Fixture { Floating = true, ClockNow = wall };
            await using var client = await f.Open();
            await client.ActivateAsync("synthetic-key");
            elapsed += 60 * TimeSpan.TicksPerSecond; wall += 60; f.ClockNow = wall;
            // Wake the existing worker without performing a refresh operation.
            var lifetime = (InstalledLifetime)typeof(OrbitClient).GetField("lifetime", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(client)!;
            lifetime.Signal();
            for (var attempt = 0; attempt < 300 && client.Snapshot().Session?.Sequence != 2; attempt++) await Task.Delay(10);
            Require(client.Snapshot().Session?.Sequence == 2 && f.SessionRenewals == 1,
                "automatic worker must renew a still-valid session at refresh_after");
            f.DenySessionRenewal = true; f.DenySessionStart = true;
            elapsed += 60 * TimeSpan.TicksPerSecond; wall += 60; f.ClockNow = wall;
            lifetime.Signal();
            for (var attempt = 0; attempt < 300 && client.Snapshot().Session != null; attempt++) await Task.Delay(10);
            Require(client.Snapshot().Access != Access.Online && client.Snapshot().Session == null);
            var requests = f.SessionStarts + f.SessionRenewals;
            await Task.Delay(150);
            Require(f.SessionStarts + f.SessionRenewals == requests, "terminal renewal denial must not spin the worker");
            var prompts = 0;
            await Expect(OrbitError.Denied, () => client.EnsureAccessAsync("export", _ =>
            { prompts++; return ValueTask.FromResult<string?>("must-not-prompt"); }));
            Require(prompts == 0);
        }
        finally { Clock.SetTestClock(null); }
    }

    private static async Task UnknownSessionEnd()
    {
        await using var f = new Fixture { Floating = true };
        await using var client = await f.Open();
        await client.ActivateAsync("synthetic-key");
        typeof(OrbitClient).GetField("sessionProfileKnown", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(client, false);
        typeof(OrbitClient).GetField("sessionRequired", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(client, false);
        var starts = f.SessionStarts;
        await client.EndSessionAsync();
        await Expect(OrbitError.Denied, () => client.RequireAccessAsync("export"));
        Require(f.SessionStarts == starts, "ending an unknown floating policy must suppress acquisition before metadata validation");
    }

    private static async Task EndDuringInitialActivation()
    {
        await using var f = new Fixture { Floating = true, Mode = 6,
            Received = new(TaskCreationOptions.RunContinuationsAsynchronously),
            Release = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        await using var client = await f.Open();
        var activation = client.ActivateAsync("synthetic-key");
        await f.Received.Task.WaitAsync(TimeSpan.FromSeconds(3));
        try { Require((await client.EndSessionAsync()).Access != Access.Online); }
        finally { f.Release.TrySetResult(); }
        await Expect(OrbitError.StaleResponse, () => activation);
        Require(client.Snapshot().Access != Access.Online && f.SessionStarts == 0,
            "late activation must not undo the newer end intent");
        f.Mode = 0;
        await client.ActivateAsync("synthetic-key");
        Require(client.Snapshot().Access == Access.Online && f.SessionStarts == 1,
            "a later explicit activation may intentionally restore access");
    }

    private static async Task SessionFences()
    {
        foreach (var action in new[] { "end", "logout", "close", "cancel" })
        foreach (var denied in new[] { false, true })
        {
            await using var f = new Fixture { Floating = true };
            await using var client = await f.Open();
            await client.ActivateAsync("synthetic-key");
            await client.EndSessionAsync();
            f.SessionReceived = new(TaskCreationOptions.RunContinuationsAsynchronously);
            f.SessionRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);
            using var cancellation = new CancellationTokenSource();
            var start = client.StartSessionAsync(cancellation.Token);
            await f.SessionReceived.Task.WaitAsync(TimeSpan.FromSeconds(3));
            f.DenySessionStart = denied;
            Task transition = Task.CompletedTask;
            if (action == "end") transition = client.EndSessionAsync();
            if (action == "logout") client.Logout();
            if (action == "close") transition = client.DisposeAsync().AsTask();
            if (action == "cancel") cancellation.Cancel();
            f.SessionRelease.TrySetResult();
            try { await start; throw new InvalidOperationException("blocked start restored authority"); }
            catch (OrbitException) { }
            await transition;
            if (action != "close") Require(client.Snapshot().Access != Access.Online);
        }
    }

    private static async Task SessionNoOps()
    {
        await using (var ordinary = new Fixture())
        await using (var client = await ordinary.Open())
        {
            await ordinary.Activate(client);
            var starts = ordinary.SessionStarts;
            var start = await client.StartSessionAsync();
            var end = await client.EndSessionAsync();
            Require(start.Access == Access.Online && end.Access == Access.Online &&
                ordinary.SessionStarts == starts && ordinary.SessionEnds == 0,
                "ordinary licences must not issue session requests");
        }

        await using (var offlineFixture = new Fixture())
        await using (var client = await offlineFixture.Open())
        {
            var installation = client.CreateOfflineRequest().InstallationId;
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var file = offlineFixture.SignOffline(installation, 1, "session_noop_offline", now, now + 120);
            var imported = client.ImportOfflineFile(file);
            var starts = offlineFixture.SessionStarts;
            Require((await client.StartSessionAsync()).OfflineFileMode &&
                (await client.EndSessionAsync()).OfflineFileMode && offlineFixture.SessionStarts == starts,
                "offline-file mode must not start or release a connected session");
        }
    }

    private static async Task OnlineRestart()
    {
        await using var f = new Fixture();
        await using (var c = await f.Open())
        {
            await f.Activate(c);
            Require((await c.RequireAccessAsync("export")).Access == Access.Online);
        }
        var id = f.Record().Installation.Id;
        await using (var c = await f.Open())
        {
            Require((await c.RequireAccessAsync("export")).Access == Access.Online);
            Require(f.Record().Installation.Id == id && f.Activations == 1 && f.Validations == 1);
            await Expect(OrbitError.FeatureUnavailable, () => c.RequireAccessAsync("missing"), "feature_unavailable");
        }
    }
    private static async Task AppVersionPolicy()
    {
        await using var f = new Fixture();
        await Expect(OrbitError.Configuration, async () => { await using var c = await f.Open(appVersion: "01"); });
        var requests = new List<FixtureRequest>();
        var deny = false;
        f.OnlineResponse = request =>
        {
            lock (requests) requests.Add(request);
            return deny && request.Path.EndsWith("/validate", StringComparison.Ordinal)
                ? new FixtureReply(403, "{\"error\":{\"code\":\"app_version_unsupported\",\"message\":\"Update required\",\"request_id\":\"fixture\"}}")
                : null;
        };
        int Validations() { lock (requests) return requests.Count(r => r.Path.EndsWith("/validate", StringComparison.Ordinal)); }
        string SentVersion(string suffix)
        {
            lock (requests)
                return JsonNode.Parse(requests.Last(r => r.Path.EndsWith(suffix, StringComparison.Ordinal)).Body)!["app_version"]!.GetValue<string>();
        }
        f.UpdateAvailable = JsonNode.Parse("{\"version\":\"2.5.0\"}");
        await using (var c = await f.Open(appVersion: "2.4.1-beta.2"))
        {
            var activated = await c.ActivateAsync("synthetic-key");
            Require(activated.Access == Access.Online && activated.UpdateAvailable == "2.5.0", "activation must expose the update hint");
            Require(SentVersion("/activations") == "2.4.1-beta.2", "activation must send the app version");
            lock (requests)
                Require(requests.Count > 1 && requests.All(r => r.Headers.TryGetValue("Orbit-Client", out var header) &&
                    header == AppVersion.ClientHeader), "every request must identify the SDK");
            deny = true;
            await Expect(OrbitError.AppVersionUnsupported, () => c.RefreshAsync(), "app_version_unsupported");
            var validations = Validations();
            Require(validations == 1 && SentVersion("/validate") == "2.4.1-beta.2", "denied validation must be sent once with the app version");
            var snapshot = c.Snapshot();
            Require(snapshot.Access == Access.RefreshRequired && !snapshot.HasFeature("export") && snapshot.UpdateAvailable == null,
                "an unsupported version must not fall back to cached or offline access");
            var prompted = false;
            await Expect(OrbitError.AppVersionUnsupported, () => c.EnsureAccessAsync("export", _ =>
            {
                prompted = true;
                return ValueTask.FromResult<string?>("replacement-key");
            }));
            Require(!prompted && Validations() == validations, "paced access checks must not prompt or retry");
            Require(f.Record().Credential != null && f.Record().Access == null, "the activation must remain without cached access");
        }
        await using (var c = await f.Open(appVersion: "2.4.1-beta.2"))
            await Expect(OrbitError.AppVersionUnsupported, () => c.RequireAccessAsync("export"));
    }
    private static async Task OfflineFiles()
    {
        long elapsed = 10 * TimeSpan.TicksPerSecond;
        long wall = 1_800_000_000;
        Clock.SetTestClock(() => new ClockStart(Volatile.Read(ref elapsed), Volatile.Read(ref wall)));
        try
        {
            await using var f = new Fixture();
            var requestsBefore = f.Server.RequestCount;
            string installation;
            string first;
            string renewed;
            await using (var client = await f.Open())
            {
                var request = client.CreateOfflineRequest();
                installation = request.InstallationId;
                using var json = JsonDocument.Parse(JsonSerializer.Serialize(request));
                Require(json.RootElement.GetProperty("format").GetString() == "orbit-offline-request" &&
                    json.RootElement.GetProperty("version").GetInt32() == 1 &&
                    json.RootElement.GetProperty("fingerprint").ValueKind == JsonValueKind.Null);
                first = f.SignOffline(installation, 1, "offline_issue_1", wall, wall + 120);
                var imported = client.ImportOfflineFile(" \t" + first + "\n");
                Require(imported.Access == Access.Offline && imported.OfflineFileMode &&
                    imported.ExpiresAt == DateTimeOffset.FromUnixTimeSeconds(wall + 120) && imported.HasFeature("export"));
                Require((await client.RequireAccessAsync("export")).Access == Access.Offline);
                await Expect(OrbitError.FeatureUnavailable, () => client.RequireAccessAsync("missing"), "feature_unavailable");
                var saved = f.Record();
                Require(saved.Format == 3 && saved.Offline?.Jws == first && saved.Offline.Sequence == 1 &&
                    saved.Credential == null && saved.Access == null && saved.PendingActivation == null,
                    "format-3 import must persist only offline authority");
                var equivalent = f.SignOffline(installation, 1, "offline_issue_1", wall, wall + 120, reverseFields: true);
                Require(client.ImportOfflineFile(equivalent).Access == Access.Offline,
                    "equivalent equal-sequence import must remain active");
                elapsed += TimeSpan.TicksPerSecond / 2;
                _ = client.ImportOfflineFile(first);
                elapsed += TimeSpan.TicksPerSecond / 2;
                Require(client.ImportOfflineFile(first).RemainingOffline == TimeSpan.FromSeconds(119),
                    "reimport must count fractional elapsed time exactly once");
                Require(client.ImportOfflineFile(first).RemainingOffline == TimeSpan.FromSeconds(119),
                    "reimport without elapsed time must not move the deadline");
                var conflict = f.SignOffline(installation, 1, "offline_issue_conflict", wall, wall + 120, export: false);
                await Expect(OrbitError.Denied, () => Task.Run(() => client.ImportOfflineFile(conflict)), "offline_sequence");
                var renewalIssued = wall + 2;
                renewed = f.SignOffline(installation, 2, "offline_issue_2", renewalIssued, renewalIssued + 240);
                Require(client.ImportOfflineFile(renewed).RemainingOffline == TimeSpan.FromSeconds(240),
                    "a future-skewed renewal must advance the original anchor only to the signed time floor");
                Require(client.ImportOfflineFile(renewed).RemainingOffline == TimeSpan.FromSeconds(240),
                    "repeating a future-skewed renewal without elapsed time must not move its deadline");
                elapsed += 4 * TimeSpan.TicksPerSecond;
                wall += 4;
                Require(client.ImportOfflineFile(renewed).RemainingOffline == TimeSpan.FromSeconds(236),
                    "a renewed file must count whole elapsed seconds exactly once");
                await Expect(OrbitError.InvalidResponse, () => Task.Run(() => client.ImportOfflineFile(first)));
                Require(f.Server.RequestCount == requestsBefore);
            }
            await Expect(OrbitError.Configuration, async () =>
            {
                await using var missingKeys = await f.Open(withOfflineKeys: false);
            }, "offline_keys_required");
            Require(f.Record().Offline?.Jws != null && f.Server.RequestCount == requestsBefore);
            wall += 241;
            elapsed = 2 * TimeSpan.TicksPerSecond;
            await using (var client = await f.Open())
            {
                Require(client.Snapshot().Access == Access.Expired && client.Snapshot().OfflineFileMode);
                await Expect(OrbitError.Denied, () => client.RequireAccessAsync("export"), "offline_file_expired");
                var refresh = await client.RefreshAsync();
                Require(refresh.Access == Access.Expired && refresh.OfflineFileMode && f.Server.RequestCount == requestsBefore);
                var refreshIfDue = (Task<Snapshot>)typeof(OrbitClient)
                    .GetMethod("RefreshIfDueAsync", BindingFlags.NonPublic | BindingFlags.Instance)!
                    .Invoke(client, [CancellationToken.None])!;
                var guardedRefresh = await refreshIfDue;
                Require(guardedRefresh.Access == Access.Expired && guardedRefresh.OfflineFileMode &&
                    f.Server.RequestCount == requestsBefore,
                    "the background refresh guard must return an expired local file snapshot without HTTP");
                var prompts = 0;
                await Expect(OrbitError.Denied, () => client.EnsureAccessAsync("export", _ =>
                {
                    prompts++;
                    return ValueTask.FromResult<string?>("unexpected-key");
                }), "offline_file_expired");
                Require(prompts == 0, "expired offline file must never prompt for an activation key");
                var next = f.SignOffline(installation, 3, "offline_issue_3", wall, wall + 120);
                Require(client.ImportOfflineFile(next).Access == Access.Offline);
                wall++;
                elapsed += TimeSpan.TicksPerSecond;
                Require(client.Snapshot().Access == Access.Offline,
                    $"offline authority must still validate before logout (elapsed={elapsed}, wall={wall})");
                client.Logout();
                var record = f.Record();
                Require(record.Offline?.Sequence == 3 && record.Offline.Jws == null &&
                    record.Offline.TimeHighWater >= wall && record.Offline.WallHighWater >= wall &&
                    client.Snapshot().Access == Access.Denied && f.Server.RequestCount == requestsBefore,
                    $"logout must clear authority while checkpointing the same offline time floor (record={record.Offline?.Sequence}/{record.Offline?.Jws is null}/{record.Offline?.TimeHighWater}/{record.Offline?.WallHighWater}, wall={wall}, access={client.Snapshot().Access}, requests={f.Server.RequestCount}/{requestsBefore})");
                elapsed += 121 * TimeSpan.TicksPerSecond;
                await Expect(OrbitError.ClockUncertain,
                    () => Task.Run(() => client.ImportOfflineFile(next)));
                wall += 121;
                await Expect(OrbitError.InvalidResponse,
                    () => Task.Run(() => client.ImportOfflineFile(next)));
            }
            Require(f.Server.RequestCount == requestsBefore);
        }
        finally { Clock.SetTestClock(null); }
    }
    private static async Task OfflineTransitionFloors()
    {
        foreach (var accountTransition in new[] { false, true })
        {
            var stage = "clock setup";
            long elapsed = Clock.ElapsedTicks();
            long wall = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Clock.SetTestClock(() => new ClockStart(Volatile.Read(ref elapsed), Volatile.Read(ref wall)));
            try
            {
                await using var f = new Fixture();
                stage = "open client";
                await using var client = await f.Open();
                var installation = client.CreateOfflineRequest().InstallationId;
                var issued = wall;
                var file = f.SignOffline(installation, 1, "offline_transition_floor", issued, issued + 120);
                stage = "initial import";
                Require(client.ImportOfflineFile(file).Access == Access.Offline);
                stage = "transition";
                try
                {
                    if (accountTransition)
                    {
                        stage = "account login";
                        await client.LoginAsync("alice", "synthetic password");
                        stage = "account logout";
                        await client.LogoutAccountAsync();
                    }
                    else
                    {
                        stage = "online activation";
                        await client.ActivateAsync("synthetic-key");
                    }
                }
                catch (OrbitException error)
                {
                    throw new InvalidOperationException($"transition {(accountTransition ? "account" : "online")} failed before floor check: {error.Error}/{error.Code}", error);
                }
                catch (Exception error)
                {
                    throw new InvalidOperationException($"transition {(accountTransition ? "account" : "online")} failed before floor check: {error.GetType().Name}/{error.Message}", error);
                }
                stage = "local logout";
                client.Logout();
                stage = "post-transition reimport";
                elapsed += 7 * TimeSpan.TicksPerSecond;
                wall += 7;
                Require(client.ImportOfflineFile(file).RemainingOffline == TimeSpan.FromSeconds(113),
                    "a transition must retain the original offline anchor and report exact remaining time");
                Require(client.ImportOfflineFile(file).RemainingOffline == TimeSpan.FromSeconds(113),
                    "a repeated post-transition import must not move the offline deadline");
                elapsed += 2 * TimeSpan.TicksPerSecond;
                wall += 2;
                Require(client.ImportOfflineFile(file).RemainingOffline == TimeSpan.FromSeconds(111),
                    "a post-transition renewal must count whole elapsed seconds exactly once");
                client.Logout();
                var checkpoint = f.Record().Offline;
                Require(checkpoint != null && checkpoint.Jws == null && checkpoint.Sequence == 1 &&
                    checkpoint.TimeHighWater >= issued + 9 && checkpoint.WallHighWater >= issued + 9,
                    "transition logout must preserve the updated durable clock floor");
                var requests = f.Server.RequestCount;
                elapsed += 121 * TimeSpan.TicksPerSecond;
                await Expect(OrbitError.ClockUncertain,
                    () => Task.Run(() => client.ImportOfflineFile(file)));
                Require(f.Server.RequestCount == requests && f.Record().Offline?.Jws == null,
                    "an unrelated account or online transition must retain the offline time anchor without restoring authority");
            }
            catch (Exception error)
            {
                throw new InvalidOperationException($"offline transition {(accountTransition ? "account" : "online")} failed during {stage}: {error.GetType().Name}/{error.Message}", error);
            }
            finally { Clock.SetTestClock(null); }
        }
    }

    private static async Task OfflineDurableFences()
    {
        foreach (var scenario in new[] { "cancel-save", "cancel-checkpoint", "expire-during-write" })
        {
            long elapsed = 10 * TimeSpan.TicksPerSecond;
            long wall = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Clock.SetTestClock(() => new ClockStart(Volatile.Read(ref elapsed), Volatile.Read(ref wall)));
            try
            {
                await using var f = new Fixture();
                var token = new CancellationTokenSource();
                await using (var client = await f.Open())
                {
                    var installation = client.CreateOfflineRequest().InstallationId;
                    var file = f.SignOffline(installation, 1, "offline_durable_fence", wall, wall + 120);
                    InstalledStorageDiagnostics.OfflineWriteCompleted = stage =>
                    {
                        if (scenario == "cancel-save" && stage == "save") token.Cancel();
                        if (scenario == "cancel-checkpoint")
                        {
                            if (stage == "save") { elapsed += TimeSpan.TicksPerSecond; wall++; }
                            if (stage == "checkpoint") token.Cancel();
                        }
                        if (scenario == "expire-during-write" && stage == "save")
                        {
                            elapsed += 121 * TimeSpan.TicksPerSecond;
                            wall += 121;
                        }
                    };
                    try
                    {
                        if (scenario == "expire-during-write")
                            await Expect(OrbitError.Denied,
                                () => Task.Run(() => client.ImportOfflineFile(file)), "offline_file_expired");
                        else
                            await Expect(OrbitError.Cancelled,
                                () => Task.Run(() => client.ImportOfflineFile(file, token.Token)));
                    }
                    finally { InstalledStorageDiagnostics.OfflineWriteCompleted = null; }
                    var saved = f.Record().Offline;
                    Require(saved is { Jws: null, Sequence: 1 } &&
                        (scenario != "expire-during-write" || saved.TimeHighWater >= wall),
                        "cancelled or expired durable import must clear its JWS and retain observed time floors");
                }
                await using var reopened = await f.Open();
                Require(reopened.Snapshot().Access == Access.Denied && !reopened.Snapshot().OfflineFileMode,
                    "a cleared durable offline import must not restore after restart");
            }
            finally
            {
                InstalledStorageDiagnostics.OfflineWriteCompleted = null;
                Clock.SetTestClock(null);
            }
        }
    }

    private static async Task OfflineStaleImport()
    {
        await using var f = new Fixture();
        await using var client = await f.Open();
        var request = client.CreateOfflineRequest();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var file = f.SignOffline(request.InstallationId, 1, "offline_stale_import", now, now + 120);
        f.Mode = 6;
        f.Received = new(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var queued = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        InstalledStorageDiagnostics.OfflineImportQueued = () => queued.TrySetResult();
        try
        {
            var activation = client.ActivateAsync("synthetic-key");
            await f.Received.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var import = Task.Run(() => client.ImportOfflineFile(file));
            await queued.Task.WaitAsync(TimeSpan.FromSeconds(5));
            client.Logout();
            f.Release.TrySetResult();
            await Expect(OrbitError.StaleResponse, () => activation);
            await Expect(OrbitError.StaleResponse, () => import);
            var saved = f.Record();
            Require(saved.Credential == null && saved.Access == null && saved.PendingActivation == null &&
                client.Snapshot().Access == Access.Denied && f.Activations == 1,
                "logout must fence an import queued behind activation and prevent authority resurrection");
        }
        finally
        {
            InstalledStorageDiagnostics.OfflineImportQueued = null;
            f.Release.TrySetResult();
        }
    }
    private static async Task OfflineRestart()
    {
        await using var f = new Fixture();
        DateTimeOffset? expiry;
        await using (var c = await f.Open())
        {
            await f.Activate(c);
            expiry = c.Snapshot().ExpiresAt;
        }
        f.Mode = 1;
        await using (var c = await f.Open())
        {
            var state = await c.RequireAccessAsync("export");
            Require(state.Access == Access.Offline && state.ExpiresAt == expiry && f.Validations == 1);
        }
    }
    private static async Task StrictRestart()
    {
        await using var f = new Fixture { Offline = false };
        await using (var c = await f.Open())
            await f.Activate(c);
        f.Mode = 1;
        await using (var c = await f.Open())
            await Expect(OrbitError.Transient, () => c.RequireAccessAsync("export"));
        Require(f.Activations == 1);
    }
    private static async Task PendingIdentity()
    {
        await using var f = new Fixture { Mode = 1 };
        await using (var c = await f.Open())
            await Expect(OrbitError.Transient, () => c.ActivateAsync("synthetic-key"));
        var pending = f.Record().PendingActivation!;
        f.Mode = 0;
        await using (var c = await f.Open())
        {
            await Expect(OrbitError.Storage, () => c.ActivateAsync("other-key"), "pending_activation");
            await f.Activate(c);
        }
        Require(f.Operations.Count == 2 && f.Operations.All(id => id == pending.OperationId) && f.Record().PendingActivation == null);
    }
    private static async Task PendingAccountIdentity()
    {
        await using var f = new Fixture { Mode = 1 };
        const string password = "never-persist-account-password";
        var accountSession = new string('s', 43);
        await using (var client = await f.Open())
        {
            var account = await client.LoginAsync("alice", password);
            Require(account.Customer.Id == "customer_1");
            await Expect(OrbitError.Transient, () => client.ActivateAccountAsync("licence"));
        }

        var uncertain = f.Record();
        var pending = uncertain.PendingActivation!;
        Require(pending.PrincipalKind == "account" && f.Operations.Count == 1 &&
            f.Operations[0] == pending.OperationId && uncertain.Credential == null && uncertain.Access == null);
        var saved = File.ReadAllText(System.IO.Path.Combine(f.Path, "orbit-storage.bin"));
        Require(!saved.Contains(password, StringComparison.Ordinal) &&
            !saved.Contains(accountSession, StringComparison.Ordinal) &&
            !saved.Contains("customer_session", StringComparison.Ordinal));

        f.Mode = 0;
        f.LoginDenied = true;
        await using (var client = await f.Open())
            await Expect(OrbitError.Denied, () => client.LoginAsync("alice", "wrong-account-password"));
        var afterFailedLogin = f.Record();
        Require(afterFailedLogin.PendingActivation?.OperationId == pending.OperationId &&
            afterFailedLogin.Credential == null && afterFailedLogin.Access == null);
        saved = File.ReadAllText(System.IO.Path.Combine(f.Path, "orbit-storage.bin"));
        Require(!saved.Contains(password, StringComparison.Ordinal) &&
            !saved.Contains("wrong-account-password", StringComparison.Ordinal) &&
            !saved.Contains(accountSession, StringComparison.Ordinal));

        f.LoginDenied = false;
        await using (var client = await f.Open())
        {
            var account = await client.LoginAsync("alice", password);
            Require(account.Customer.Id == "customer_1");
            await client.ActivateAccountAsync("licence");
        }
        var recovered = f.Record();
        Require(f.Operations.Count == 2 && f.Operations.All(id => id == pending.OperationId) &&
            recovered.PendingActivation == null && recovered.Credential != null);
        saved = File.ReadAllText(System.IO.Path.Combine(f.Path, "orbit-storage.bin"));
        Require(!saved.Contains(password, StringComparison.Ordinal) &&
            !saved.Contains(accountSession, StringComparison.Ordinal));
    }
    private static async Task IdentityMismatch()
    {
        await using var f = new Fixture();
        const string firstFingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const string secondFingerprint = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        string originalId;
        await using (var client = await f.Open(fingerprint: firstFingerprint, provider: "custom:fixture", disableMachineBinding: false))
        {
            await f.Activate(client);
            originalId = f.Record(firstFingerprint, "custom:fixture").Installation.Id;
        }
        await using (var client = await f.Open(fingerprint: secondFingerprint, provider: "custom:fixture", disableMachineBinding: false))
        {
            var changed = f.Record(secondFingerprint, "custom:fixture");
            Require(changed.Installation.Id != originalId && changed.Credential == null &&
                changed.PendingActivation == null && changed.Access == null &&
                changed.Installation.Fingerprint == secondFingerprint && f.Validations == 0);
            await f.Activate(client);
            Require(f.Operations.Count == 2 && changed.Installation.Id != originalId);
        }
        var currentId = f.Record(secondFingerprint, "custom:fixture").Installation.Id;
        await using (var client = await f.Open(disableMachineBinding: true))
        {
            var unavailable = f.Record();
            Require(unavailable.Installation.Id != currentId && unavailable.Credential == null &&
                unavailable.PendingActivation == null && unavailable.Access == null &&
                unavailable.Installation.Fingerprint == null && f.Validations == 0);
        }

        await using var offlineFixture = new Fixture();
        const string oldOfflineFingerprint = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        const string newOfflineFingerprint = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        string offlineInstallation;
        await using (var oldIdentity = await offlineFixture.Open(fingerprint: oldOfflineFingerprint,
            provider: "custom:fixture", disableMachineBinding: false))
        {
            offlineInstallation = oldIdentity.CreateOfflineRequest().InstallationId;
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var file = offlineFixture.SignOffline(offlineInstallation, 1, "offline_machine_change", now, now + 120);
            Require(oldIdentity.ImportOfflineFile(file).Access == Access.Offline);
        }
        await using (var newIdentity = await offlineFixture.Open(fingerprint: newOfflineFingerprint,
            provider: "custom:fixture", disableMachineBinding: false))
        {
            var changed = offlineFixture.Record(newOfflineFingerprint, "custom:fixture");
            Require(changed.Installation.Id != offlineInstallation && changed.Offline == null &&
                newIdentity.Snapshot().Access == Access.Denied,
                "a changed device identity must rotate scope and discard stored offline authority");
        }
    }
    private static async Task MalformedIdentity()
    {
        foreach (var mode in new[] { 3, 4, 5 })
        {
            await using var f = new Fixture { Mode = mode };
            await using (var c = await f.Open())
                await Expect(OrbitError.InvalidResponse, () => c.ActivateAsync("synthetic-key"));
            Require(f.Record().PendingActivation != null);
            f.Mode = 0;
            await using (var c = await f.Open())
                await f.Activate(c);
            Require(f.Operations[0] == f.Operations[1]);
        }
    }
    private static async Task PendingFence()
    {
        await using var f = new Fixture();
        await using (var c = await f.Open())
            await f.Activate(c);
        var original = f.Record();
        f.Mode = 1;
        await using (var c = await f.Open())
            await Expect(OrbitError.Transient, () => c.ActivateAsync("synthetic-key"));
        var uncertain = f.Record();
        f.WriteRecord(uncertain with
        {
            Credential = original.Credential,
            Access = original.Access
        });
        f.Mode = 0;
        var requests = f.Validations;
        await using (var c = await f.Open())
        {
            Require(f.Validations == requests && f.Record().Access == null);
            await Expect(OrbitError.Storage, () => c.RefreshAsync(), "pending_activation");
            await Expect(OrbitError.Storage, () => c.RequireAccessAsync("export"), "pending_activation");
            await Task.Delay(100);
            Require(f.Validations == requests && f.Record().PendingActivation == uncertain.PendingActivation);
            await f.Activate(c);
            Require(f.Operations[^1] == uncertain.PendingActivation!.OperationId);
        }
    }
    private static async Task CredentialValidation()
    {
        foreach (var mode in new[] { 4, 5, 7 })
        {
            await using var f = new Fixture();
            await using (var client = await f.Open()) await f.Activate(client);
            f.Mode = mode;
            await Expect(OrbitError.InvalidResponse, async () => { await using var client = await f.Open(); });
            Require(f.Record().Access == null);
        }
        await using var finite = new Fixture();
        await using (var client = await finite.Open()) await finite.Activate(client);
        var record = finite.Record();
        finite.FiniteExpiry = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 86400;
        finite.WriteRecord(record with { Credential = record.Credential! with { ExpiresAt = finite.FiniteExpiry }, Access = null });
        await using (var client = await finite.Open())
        {
            Require((await client.RequireAccessAsync("export")).CredentialExpiresAt == DateTimeOffset.FromUnixTimeSeconds(finite.FiniteExpiry!.Value));
            Require(finite.Record().Credential!.ExpiresAt == finite.FiniteExpiry);
            finite.FiniteExpiry = null;
            await Expect(OrbitError.InvalidResponse, () => client.RefreshAsync());
        }
    }
    private static async Task PendingExpiry()
    {
        await using var f = new Fixture { Mode = 1 };
        await using (var c = await f.Open())
            await Expect(OrbitError.Transient, () => c.ActivateAsync("synthetic-key"));
        var r = f.Record();
        f.WriteRecord(r with
        {
            PendingActivation = r.PendingActivation! with
            {
                CreatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 86400
            }
        });
        f.Mode = 0;
        await using (var c = await f.Open())
        {
            await Expect(OrbitError.Storage, () => c.ActivateAsync("synthetic-key"), "pending_activation_expired");
            Require(f.Activations == 1);
            c.Logout();
            await f.Activate(c);
            Require(f.Operations[0] != f.Operations[1]);
        }
    }
    private static async Task DeniedRestart()
    {
        await using var f = new Fixture();
        await using (var c = await f.Open())
            await f.Activate(c);
        f.Mode = 8;
        await Expect(OrbitError.Denied, async () => { await using var c = await f.Open(); });
        Require(f.Record().Access == null && f.Record().Credential != null, "suspension discarded the credential");
        f.Mode = 2;
        await Expect(OrbitError.Denied, async () => { await using var c = await f.Open(); });
        Require(f.Record().Access == null && f.Record().Credential == null);
    }
    private static async Task InvalidCache()
    {
        foreach (var kind in new[] { "rollback", "progress", "signature", "expiry" })
        {
            await using var f = new Fixture();
            await using (var c = await f.Open())
                await f.Activate(c);
            var record = f.Record();
            var a = record.Access!;
            a = kind switch
            {
                "rollback" => a with { WallHighWater = a.WallHighWater + 60 },
                "progress" => a with { ServerHighWater = a.ServerHighWater + 60 },
                "expiry" => a with { ReceivedWallTime = a.ReceivedWallTime - 7200, WallHighWater = a.WallHighWater - 7200 },
                _ => a with { Jws = BadSignature(a.Jws) }
            };
            f.WriteRecord(record with
            {
                Access = a
            });
            f.Mode = 1;
            await using (var c = await f.Open())
            {
                await Expect(OrbitError.Transient, () => c.RequireAccessAsync("export"));
                Require(f.Record().Access == null);
            }
        }
    }
    private static string BadSignature(string token)
    {
        var parts = token.Split('.');
        var bytes = JsonWire.DecodeBase64(parts[2]);
        bytes[0] ^= 1;
        parts[2] = JsonWire.EncodeBase64(bytes);
        return string.Join('.', parts);
    }
    private static async Task CloseClock()
    {
        await using var f = new Fixture();
        var c = await f.Open();
        await f.Activate(c);
        var start = Clock.Capture();
        typeof(OrbitClient).GetField("anchor", BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(c, new ClockAnchor(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), start with
        {
            WallSeconds = start.WallSeconds + 60
        }));
        await Expect(OrbitError.ClockUncertain, () => c.DisposeAsync().AsTask());
        Require(f.Record().Access == null);
        f.Mode = 1;
        await using (var reopened = await f.Open())
            await Expect(OrbitError.Transient, () => reopened.RequireAccessAsync("export"));
    }
    private static async Task CloseDuringRequest()
    {
        await using var f = new Fixture();
        var c = await f.Open();
        await f.Activate(c);
        f.Mode = 6;
        f.Received = new(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var refresh = c.RefreshAsync();
        await f.Received.Task;
        await c.DisposeAsync();
        await Expect(OrbitError.Cancelled, () => refresh);
        f.Mode = 0;
        f.Release.TrySetResult();
        await using var reopened = await f.Open();
        Require((await reopened.RequireAccessAsync("export")).Access == Access.Online);
    }
    private static async Task Codec()
    {
        await using var f = new Fixture();
        await using (var c = await f.Open())
            await f.Activate(c);
        var record = f.Record();
        var bytes = InstalledCodec.Encode(record);
        Require(!Encoding.UTF8.GetString(bytes).Contains("synthetic-key", StringComparison.Ordinal));
        var decodedFormat2 = InstalledCodec.Decode(bytes, f.Scope, record.Provider, null, null);
        Require(decodedFormat2.Format == 2 && decodedFormat2.Installation.Id == record.Installation.Id,
            "format-2 decode must preserve the installation ID");
        foreach (var field in new[] { "credential", "pending_activation", "access", "scope", "installation" })
        {
            var node = JsonNode.Parse(bytes)!.AsObject();
            node.Remove(field);
            await Expect(OrbitError.Storage, () => { _ = InstalledCodec.Decode(Encoding.UTF8.GetBytes(node.ToJsonString()), f.Scope, record.Provider, null, null); return Task.CompletedTask; });
        }
        var text = Encoding.UTF8.GetString(bytes);
        foreach (var bad in new[] { text[..^1] + ",\"format\":2}", text.Replace("\"credential\":{", "\"credential\":{\"password\":\"secret\",", StringComparison.Ordinal) })
            await Expect(OrbitError.Storage, () => { _ = InstalledCodec.Decode(Encoding.UTF8.GetBytes(bad), f.Scope, record.Provider, null, null); return Task.CompletedTask; });
        var offlineRecord = record with
        {
            Format = 3, Credential = null, PendingActivation = null, Access = null,
            Offline = new InstalledOffline(null, 1, "offline_codec", new string('a', 64), 1800000000, 1800000000, 1800000000)
        };
        var format3 = Encoding.UTF8.GetString(InstalledCodec.Encode(offlineRecord));
        var duplicateOffline = format3.Replace("\"offline\":{", "\"offline\":{},\"offline\":{", StringComparison.Ordinal);
        await Expect(OrbitError.Storage, () =>
        {
            _ = InstalledCodec.Decode(Encoding.UTF8.GetBytes(duplicateOffline), f.Scope, record.Provider, null, null);
            return Task.CompletedTask;
        });
    }
    private static async Task Files()
    {
        await using var f = new Fixture();
        await using (var c = await f.Open())
        {
            await Expect(OrbitError.Storage, async () => { await using var duplicate = await f.Open(); }, "installation_in_use");
        }
        File.Delete(System.IO.Path.Combine(f.Path, "orbit-storage.bin"));
        await Expect(OrbitError.Storage, async () => { await using var c = await f.Open(); });
        if (OperatingSystem.IsWindows())
        {
            var unsafePath = System.IO.Path.Combine(f.Root, "unsafe");
            Directory.CreateDirectory(unsafePath);
            await Expect(OrbitError.Storage, async () => { await using var c = await f.Open(unsafePath); });
            Require(Directory.GetFileSystemEntries(unsafePath).Length == 0);
            using var identity = WindowsIdentity.GetCurrent();
            await WindowsIdentity.RunImpersonatedAsync(identity.AccessToken, () => Expect(OrbitError.Storage, async () => { await using var c = await f.Open(System.IO.Path.Combine(f.Root, "impersonated")); }));
        }
        if (OperatingSystem.IsLinux())
        {
            var unsafePath = System.IO.Path.Combine(f.Root, "unsafe");
            Directory.CreateDirectory(unsafePath);
            File.SetUnixFileMode(unsafePath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead);
            await Expect(OrbitError.Storage, async () => { await using var c = await f.Open(unsafePath); });
            Require(File.GetUnixFileMode(unsafePath).HasFlag(UnixFileMode.GroupRead));
        }
    }
    private static Task MacOSDirectoryReplacement()
    {
        if (!OperatingSystem.IsMacOS()) return Task.CompletedTask;
        var root = Directory.CreateTempSubdirectory("orbit-macos-lease-");
        var path = System.IO.Path.Combine(root.FullName, "state");
        var moved = path + "-moved";
        try
        {
            using var lease = MacOSStorageLease.Open(path, installed: true);
            lease.BeforeLeaseCommitForTest = () =>
            {
                Directory.Move(path, moved);
                Directory.CreateDirectory(path);
                SetMacPrivateDirectoryMode(path);
            };
            try
            {
                lease.WriteInstalled([1, 2, 3], allowMissing: true);
                throw new InvalidOperationException("A renamed pinned directory accepted a lease commit");
            }
            catch (OrbitException error) when (error.Error == OrbitError.Storage) { }
            Require(new FileInfo(System.IO.Path.Combine(moved, MacOSStorageLease.LeaseName)).Length == 1);
            Require(!File.Exists(System.IO.Path.Combine(moved, "orbit-storage.bin")));
        }
        finally { Directory.Delete(root.FullName, recursive: true); }
        return Task.CompletedTask;
    }
    private static void SetMacPrivateDirectoryMode(string path)
    {
        if (!OperatingSystem.IsMacOS()) throw new PlatformNotSupportedException();
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
    private static async Task PreviousBearer()
    {
        await using var f = new Fixture();
        await using var c = await f.Open();
        var previous = new string('p', 43);
        _ = await c.ActivateWithPreviousAsync("synthetic-key", previous, "operation_123456");
        Require(f.Previous == previous);
    }
    [DllImport("libc.so.6", EntryPoint = "link", SetLastError = true)]
    private static extern int HardLink(string source, string target);
    private static async Task InterruptedFiles()
    {
        await using (var f = new Fixture())
        {
            await using (var c = await f.Open())
                await f.Activate(c);
            File.WriteAllBytes(System.IO.Path.Combine(f.Path, WindowsStorage.LockName), [1]);
            await Expect(OrbitError.Storage, async () => { await using var c = await f.Open(); });
            Require(File.ReadAllBytes(System.IO.Path.Combine(f.Path, WindowsStorage.LockName)).SequenceEqual(new byte[] { 1 }));
        }
        if (OperatingSystem.IsWindows())
        {
            await using var f = new Fixture();
            await using (var c = await f.Open())
                await f.Activate(c);
            var dataPath = System.IO.Path.Combine(f.Path, WindowsStorage.DataName);
            var previous = File.ReadAllBytes(dataPath);
            var entropy = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(f.Scope, InstalledCodec.Options));
            using (var files = new InstalledWindowsFiles(f.Path, entropy))
            {
                // Rejecting the protection input exercises a failure before a replacement exists.
                await Expect(OrbitError.Storage, () =>
                {
                    if (!OperatingSystem.IsWindows())
                        throw new PlatformNotSupportedException();
                    files.Write(new byte[InstalledCodec.Limit + 1]);
                    return Task.CompletedTask;
                });
            }
            Require(File.ReadAllBytes(dataPath).SequenceEqual(previous));
            Require(File.ReadAllBytes(System.IO.Path.Combine(f.Path, WindowsStorage.LockName)).SequenceEqual(new byte[] { 1 }));
            await Expect(OrbitError.Storage, async () => { await using var c = await f.Open(); });
        }
        if (!OperatingSystem.IsLinux())
            return;
        foreach (var kind in new[] { "hard", "symbolic" })
        {
            await using var f = new Fixture();
            await using (var c = await f.Open())
                await f.Activate(c);
            var data = System.IO.Path.Combine(f.Path, WindowsStorage.DataName);
            var alias = System.IO.Path.Combine(f.Path, "alias");
            if (kind == "hard")
                Require(HardLink(data, alias) == 0);
            else
            {
                File.Move(data, alias);
                File.CreateSymbolicLink(data, alias);
            }
            await Expect(OrbitError.Storage, async () => { await using var c = await f.Open(); });
        }
    }
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static async Task<WeakReference<OrbitClient>> Abandon(Fixture fixture)
    {
        var client = await fixture.Open();
        return new(client);
    }
    private static async Task Abandoned()
    {
        await using var f = new Fixture();
        var weak = await Abandon(f);
        for (var i = 0; i < 40; i++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            await Task.Delay(25);
            if (!weak.TryGetTarget(out _))
                break;
        }
        Require(!weak.TryGetTarget(out _));
        for (var i = 0; ; i++)
        {
            try
            {
                await using var reopened = await f.Open();
                break;
            }
            catch (OrbitException error) when (error.Code == "installation_in_use" && i < 40) { await Task.Delay(25); }
        }
    }
    private static async Task WorkerRetry()
    {
        await using var f = new Fixture();
        await using var c = await f.Open();
        await f.Activate(c);
        var path = System.IO.Path.Combine(f.Path, "orbit-storage.bin");
        var before = File.ReadAllBytes(path);
        for (var i = 0; i < 50; i++)
            _ = await c.RequireAccessAsync("export");
        Require(before.SequenceEqual(File.ReadAllBytes(path)));
        f.Mode = 1;
        _ = await c.RefreshAsync();
        var requests = f.Validations;
        await Task.Delay(1500);
        Require(f.Validations == requests);
    }
#endif
}
