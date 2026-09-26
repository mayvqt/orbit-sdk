using Orbit.Sdk;
#if ORBIT_LOCAL_DEVELOPMENT
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
            catch (Exception error) { failed++; Console.Error.WriteLine($"FAIL: {test.Name} ({error.GetType().Name})"); }
        }
        Console.WriteLine($"Installed client cases: {cases.Length - failed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;
#else
        await Task.CompletedTask;
        Console.Error.WriteLine("Installed fixtures require OrbitLocalDevelopment=true");
        return 2;
#endif
    }
#if ORBIT_LOCAL_DEVELOPMENT
    private const string Issuer = "https://orbit.example.test";
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
        internal readonly string Root = Directory.CreateTempSubdirectory("orbit-installed-").FullName;
        internal string Path => System.IO.Path.Combine(Root, "state");
        internal readonly LoopbackServer Server;
        internal int Mode, Activations, Validations;
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
        internal AppConfig Config => new(Server.Origin, "app", "test", Issuer, Path);
        internal InstalledScope Scope => new(Server.Origin, Issuer, "app", "test");
        internal Task<OrbitClient> Open() => OrbitClient.OpenLocalAsync(Config);
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
                fingerprint = (string?)null,
                fingerprint_provider = (string?)null,
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
                fingerprint_provider = (string?)null,
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
        internal InstalledRecord Record()
        {
            var bytes = File.ReadAllBytes(System.IO.Path.Combine(Path, "orbit-storage.bin"));
            if (OperatingSystem.IsWindows())
                bytes = WindowsDataProtection.UnprotectInstalled(bytes, SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(Scope, InstalledCodec.Options)));
            return InstalledCodec.Decode(bytes, Scope, OperatingSystem.IsWindows() ? "windows_dpapi" : "private_file", null, null);
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
            await Expect(OrbitError.Denied, () => c.RequireAccessAsync("missing"), "feature_unavailable");
        }
    }
    private static async Task OfflineRestart()
    {
        await using var f = new Fixture();
        long? expiry;
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
            Require((await client.RequireAccessAsync("export")).CredentialExpiresAt == finite.FiniteExpiry);
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
            await Expect(OrbitError.Storage, async () => { await using var c = await OrbitClient.OpenLocalAsync(f.Config with { StatePath = unsafePath }); });
            Require(Directory.GetFileSystemEntries(unsafePath).Length == 0);
            using var identity = WindowsIdentity.GetCurrent();
            await WindowsIdentity.RunImpersonatedAsync(identity.AccessToken, () => Expect(OrbitError.Storage, async () => { await using var c = await OrbitClient.OpenLocalAsync(f.Config with { StatePath = System.IO.Path.Combine(f.Root, "impersonated") }); }));
        }
        if (OperatingSystem.IsLinux())
        {
            var unsafePath = System.IO.Path.Combine(f.Root, "unsafe");
            Directory.CreateDirectory(unsafePath);
            File.SetUnixFileMode(unsafePath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead);
            await Expect(OrbitError.Storage, async () => { await using var c = await OrbitClient.OpenLocalAsync(f.Config with { StatePath = unsafePath }); });
            Require(File.GetUnixFileMode(unsafePath).HasFlag(UnixFileMode.GroupRead));
        }
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
