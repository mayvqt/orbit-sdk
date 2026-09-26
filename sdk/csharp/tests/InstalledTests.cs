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

internal static class InstalledTests
{
    internal static async Task<int> RunAsync()
    {
#if ORBIT_LOCAL_DEVELOPMENT
        (string Name, Func<Task> Run)[] cases =
        [
            ("persistent activation and online restart",OnlineRestart),
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
                Require(versionReads >= verificationCalls * 2 &&
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
        internal int Mode, Activations, Validations;
        internal bool LoginDenied;
        internal bool Offline = true;
        internal long? FiniteExpiry;
        internal readonly List<string> Operations = [];
        internal string? Previous;
        internal TaskCompletionSource? Received, Release;
        private readonly ECDsa signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        internal Fixture()
        {
            Server = new LoopbackServer(Respond);
        }
        internal string Issuer => Server.Origin;
        internal InstalledScope Scope => new(Server.Origin, Issuer, "app", "test");
        internal string? CurrentFingerprint, CurrentProvider;
        internal Task<OrbitClient> Open(string? statePath = null, string? fingerprint = null,
            string? provider = null, bool disableMachineBinding = true)
        {
            var origin = JsonWire.EncodeBase64(Encoding.UTF8.GetBytes(Server.Origin));
            var appKey = $"orbit_app_test_{origin}.app.test";
            CurrentFingerprint = fingerprint;
            CurrentProvider = fingerprint == null ? null : provider;
            return OrbitClient.OpenLocalAsync(appKey, new OrbitOptions
            {
                StatePath = statePath ?? Path,
                DisableMachineBinding = disableMachineBinding,
                Fingerprint = fingerprint == null ? null : new Fingerprint(fingerprint, provider!)
            });
        }
        internal async Task Activate(OrbitClient client) => Require((await client.ActivateAsync("synthetic-key")).Access == Access.Online);
        private async Task<FixtureReply> Respond(FixtureRequest request, CancellationToken cancellationToken)
        {
            if (request.Path.StartsWith("/.well-known/", StringComparison.Ordinal))
            {
                var key = signer.ExportParameters(false);
                return new(200, JsonSerializer.Serialize(new
                {
                    keys = new[] { new { kty = "EC", crv = "P-256", alg = "ES256", use = "sig", kid = "installed", x = JsonWire.EncodeBase64(key.Q.X!), y = JsonWire.EncodeBase64(key.Q.Y!) } }
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
            if (Mode == 2)
                return new(403, "{\"error\":{\"code\":\"licence_revoked\",\"message\":\"Denied\",\"request_id\":\"fixture\"}}");
            if (Mode == 3)
                return new(200, "{\"malformed\":true}");
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
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
            if (Mode == 4)
                response.Remove("credential_expires_at");
            if (Mode == 5)
                response["credential_expires_at"] = DateTimeOffset.FromUnixTimeSeconds(now + 86400).ToString("O");
            if (Mode == 7)
                response["credential"] = new string('r', 43);
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
            Directory.Delete(Root, true);
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
        foreach (var field in new[] { "credential", "pending_activation", "access", "scope", "installation" })
        {
            var node = JsonNode.Parse(bytes)!.AsObject();
            node.Remove(field);
            await Expect(OrbitError.Storage, () => { _ = InstalledCodec.Decode(Encoding.UTF8.GetBytes(node.ToJsonString()), f.Scope, record.Provider, null, null); return Task.CompletedTask; });
        }
        var text = Encoding.UTF8.GetString(bytes);
        foreach (var bad in new[] { text[..^1] + ",\"format\":2}", text.Replace("\"credential\":{", "\"credential\":{\"password\":\"secret\",", StringComparison.Ordinal) })
            await Expect(OrbitError.Storage, () => { _ = InstalledCodec.Decode(Encoding.UTF8.GetBytes(bad), f.Scope, record.Provider, null, null); return Task.CompletedTask; });
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
