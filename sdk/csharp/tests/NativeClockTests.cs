using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Orbit.Sdk;

internal static class NativeClockTests
{
    [DllImport("api-ms-win-core-realtime-l1-1-1.dll", EntryPoint = "QueryUnbiasedInterruptTimePrecise")]
    private static extern void QueryUnbiasedInterruptTimePrecise(out ulong ticks);

    [StructLayout(LayoutKind.Sequential)]
    private struct Timespec { public long Seconds; public long Nanoseconds; }

    [DllImport("libc", EntryPoint = "clock_gettime", SetLastError = true)]
    private static extern int ClockGetTime(int clockId, out Timespec value);

    private static long AwakeTicks()
    {
        if (OperatingSystem.IsWindows())
        {
            QueryUnbiasedInterruptTimePrecise(out var ticks);
            return checked((long)ticks);
        }
        if (!OperatingSystem.IsLinux() || !Environment.Is64BitProcess ||
            ClockGetTime(1, out var value) != 0 || value.Seconds < 0 || value.Nanoseconds is < 0 or >= 1_000_000_000)
            throw new InvalidOperationException("Supported native awake clock required");
        return checked(value.Seconds * TimeSpan.TicksPerSecond + value.Nanoseconds / 100);
    }

    internal static async Task<int> RunGrantSuspendAsync()
    {
        if (Environment.GetEnvironmentVariable("ORBIT_NATIVE_GRANT_SUSPEND_TEST") != "1")
            throw new InvalidOperationException("ORBIT_NATIVE_GRANT_SUSPEND_TEST=1 is required");
#if ORBIT_LOCAL_DEVELOPMENT
        _ = AwakeTicks();
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = signer.ExportParameters(false);
        var keys = new FixtureReply(200, JsonSerializer.Serialize(new { keys = new[] { new
        {
            kty = "EC", crv = "P-256", alg = "ES256", use = "sig", kid = "sleep_fixture",
            x = JsonWire.EncodeBase64(key.Q.X!), y = JsonWire.EncodeBase64(key.Q.Y!)
        } } }));
        var blocked = 0;
        var servers = new List<LoopbackServer>();
        var transports = new List<Transport>();
        var clients = new List<(bool Offline, OrbitClient Client, LoopbackServer Server)>();
        try
        {
            foreach (var offline in new[] { false, true })
            {
                var server = new LoopbackServer((request, _) =>
                {
                    if (Volatile.Read(ref blocked) != 0)
                        return Task.FromResult(new FixtureReply(503,
                            "{\"error\":{\"code\":\"service_unavailable\",\"message\":\"Synthetic outage\",\"request_id\":\"sleep_fixture\"}}"));
                    if (request.Method == "GET" && request.Path.StartsWith("/.well-known/orbit-jwks.json?", StringComparison.Ordinal))
                        return Task.FromResult(keys);
                    if (request.Method == "POST" && request.Path == "/api/client/v1/activations")
                        return Task.FromResult(ShortGrant(signer, offline));
                    throw new InvalidOperationException("Unexpected synthetic grant request");
                });
                servers.Add(server);
                var transport = Transport.LocalLoopback(server.Origin);
                transports.Add(transport);
                clients.Add((offline, new OrbitClient(new OrbitConfig("app", "test", "https://orbit.example.test"),
                    new Device("installation_1234"), transport), server));
            }
            var activeStart = AwakeTicks();
            var start = Clock.ElapsedTicks();
            foreach (var item in clients)
            {
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var accepted = await item.Client.ActivateAsync("synthetic licence", "sleep_operation_1234", deadline.Token);
                if (accepted.Access != Access.Online || accepted.OfflineAllowed != item.Offline || item.Server.RequestCount != 2)
                    throw new InvalidOperationException("Signed grant was not accepted through activation and key discovery");
            }
            Interlocked.Exchange(ref blocked, 1);
            foreach (var item in clients)
            {
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var accepted = await item.Client.RequireAccessAsync("export", deadline.Token);
                if (accepted.Access != Access.Online || !accepted.Entitlements.TryGetValue("export", out var enabled) ||
                    !enabled || item.Server.RequestCount != 2)
                    throw new InvalidOperationException("Positive protected access before sleep failed");
            }
            Console.WriteLine("READY: strict-online and offline-allowed grants accepted; refresh blocked. Suspend immediately for at least 45 seconds, then press Enter after resume.");
            Console.Out.Flush();
            if (Console.ReadLine() is null) throw new InvalidOperationException("EOF is not a resume acknowledgement");
            var elapsed = checked(Clock.ElapsedTicks() - start);
            var active = checked(AwakeTicks() - activeStart);
            var slept = checked(elapsed - active);
            if (elapsed < 0 || active < 0 || slept < 45 * TimeSpan.TicksPerSecond)
                throw new InvalidOperationException("At least 45 seconds of actual native sleep required");
            if (active >= 30 * TimeSpan.TicksPerSecond)
                throw new InvalidOperationException("Too much awake time; expiry during sleep was not established");
            foreach (var item in clients)
            {
                AssertExpired(item.Client.Snapshot());
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var denied = false;
                try { await item.Client.RequireAccessAsync("export", deadline.Token); }
                catch (OrbitException error) when (error.Error == OrbitError.Denied && error.Code == "access_unavailable")
                { denied = true; }
                if (!denied || item.Server.RequestCount <= 2)
                    throw new InvalidOperationException("Expired protected access did not deny after blocked refresh");
                AssertExpired(item.Client.Snapshot());
            }
            Console.WriteLine($"PASS: both signed grants expired during native sleep; access and entitlements denied. elapsed={TimeSpan.FromTicks(elapsed)}, awake={TimeSpan.FromTicks(active)}, sleep={TimeSpan.FromTicks(slept)}");
            return 0;
        }
        finally
        {
            foreach (var transport in transports) transport.Dispose();
            foreach (var server in servers) await server.DisposeAsync();
        }
#else
        await Task.CompletedTask;
        throw new InvalidOperationException("Grant sleep fixtures require OrbitLocalDevelopment=true");
#endif
    }

#if ORBIT_LOCAL_DEVELOPMENT
    private static FixtureReply ShortGrant(ECDsa signer, bool offline)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var header = JsonWire.EncodeBase64(JsonSerializer.SerializeToUtf8Bytes(new
            { alg = "ES256", typ = "orbit-access+jwt", kid = "sleep_fixture" }));
        var payload = JsonWire.EncodeBase64(JsonSerializer.SerializeToUtf8Bytes(new
        {
            iss = "https://orbit.example.test", aud = "orbit:app:test", sub = "licence", jti = "sleep_fixture",
            application_id = "app", environment_id = "test", activation_id = "activation", installation_id = "installation_1234",
            iat = now, nbf = now, exp = now + 30, refresh_after = now + 30, offline_allowed = offline,
            policy_version = 1, entitlements = new { export = true }, binding_mode = "none",
            fingerprint = (string?)null, fingerprint_provider = (string?)null, licence_expires_at = (long?)null
        }));
        var input = header + "." + payload;
        var signature = signer.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new FixtureReply(200, JsonSerializer.Serialize(new
        {
            activation_id = "activation", installation_id = "installation_1234", credential = new string('s', 43),
            credential_expires_at = Timestamp(now + 86400), server_time = Timestamp(now),
            grant = input + "." + JsonWire.EncodeBase64(signature), binding_mode = "none",
            fingerprint_provider = (string?)null, licence_expires_at = (string?)null, secret_replay_expired = false
        }));
    }

    private static string Timestamp(long value) => DateTimeOffset.FromUnixTimeSeconds(value)
        .ToString("yyyy-MM-ddTHH:mm:ss'Z'", System.Globalization.CultureInfo.InvariantCulture);

    private static void AssertExpired(Snapshot snapshot)
    {
        if (snapshot.Access != Access.Expired || snapshot.Entitlements.Count != 0 || snapshot.RemainingOfflineSeconds != 0)
            throw new InvalidOperationException("Expired grant retained access or entitlements");
    }
#endif

    internal static int RunSuspend()
    {
        if (!OperatingSystem.IsWindows())
            throw new InvalidOperationException("This native check requires Windows");
        QueryUnbiasedInterruptTimePrecise(out var activeStart);
        var start = Clock.ElapsedTicks();
        Console.WriteLine("READY: suspend/hibernate for at least two seconds, then press Enter.");
        if (Console.ReadLine() is null) throw new InvalidOperationException("No acknowledgement");
        var elapsed = checked(Clock.ElapsedTicks() - start);
        QueryUnbiasedInterruptTimePrecise(out var activeEnd);
        var active = checked((long)(activeEnd - activeStart));
        if (elapsed - active < TimeSpan.TicksPerSecond)
            throw new InvalidOperationException("No actual sleep interval observed");
        Console.WriteLine($"SDK elapsed={TimeSpan.FromTicks(elapsed)}, active elapsed={TimeSpan.FromTicks(active)}");
        return 0;
    }
}
