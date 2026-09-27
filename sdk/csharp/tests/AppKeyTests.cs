using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Orbit.Sdk;

internal static class AppKeyTests
{
    internal static void Run()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes("contracts/sdk/app-keys.json"));
        var root = document.RootElement;
        Require(root.GetProperty("format_version").GetInt32() == 1, "unexpected app-key vector version");
        var cases = root.GetProperty("cases");
        var count = 0;
        foreach (var item in cases.EnumerateArray())
        {
            var key = item.GetProperty("key").GetString()!;
            var expected = item.GetProperty("valid").GetBoolean();
            try
            {
                var parsed = AppKey.Parse(key);
                Require(expected, $"accepted invalid app-key vector: {item.GetProperty("name").GetString()}");
                Require(parsed.ApiOrigin == item.GetProperty("api_origin").GetString(), "app-key origin mismatch");
                Require(parsed.Issuer == item.GetProperty("issuer").GetString(), "app-key issuer mismatch");
                Require(parsed.ApplicationId == item.GetProperty("application_id").GetString(), "app-key application mismatch");
                Require(parsed.EnvironmentId == item.GetProperty("environment_id").GetString(), "app-key environment ID mismatch");
                Require(parsed.Environment == item.GetProperty("environment").GetString(), "app-key environment name mismatch");
            }
            catch (OrbitException error) when (error.Error == OrbitError.Configuration)
            {
                Require(!expected, $"rejected valid app-key vector: {item.GetProperty("name").GetString()}");
            }
            count++;
        }

        var loopback = "orbit_app_test_" + JsonWire.EncodeBase64(Encoding.UTF8.GetBytes("http://127.0.0.1:8123")) + ".app.test";
        ExpectConfiguration(() => AppKey.Parse(loopback));
        Require(AppKey.ParseLocal(loopback).ApiOrigin == "http://127.0.0.1:8123", "local app-key parsing rejected loopback");
        ExpectConfiguration(() => AppKey.ParseLocal("orbit_app_test_" +
            JsonWire.EncodeBase64(Encoding.UTF8.GetBytes("http://localhost:8123")) + ".app.test"));

        var production = cases.EnumerateArray().First(item => item.GetProperty("valid").GetBoolean());
        var parsedProduction = AppKey.Parse(production.GetProperty("key").GetString()!);
        var defaultFingerprint = OrbitClient.ResolveFingerprint(parsedProduction, null);
        var expectedFingerprint = NativeFingerprintOrNull(parsedProduction);
        Require(defaultFingerprint == expectedFingerprint, "default machine fingerprint resolution changed");
        Require(OrbitClient.ResolveFingerprint(parsedProduction, new OrbitOptions { DisableMachineBinding = true }) == null,
            "disabled machine binding produced a fingerprint");
        var custom = new Fingerprint(new string('a', 64), "custom:fixture.v1");
        Require(OrbitClient.ResolveFingerprint(parsedProduction, new OrbitOptions { Fingerprint = custom }) == custom,
            "custom fingerprint was not preserved");
        ExpectConfiguration(() => OrbitClient.ResolveFingerprint(parsedProduction,
            new OrbitOptions { DisableMachineBinding = true, Fingerprint = custom }));

        TestSavedFingerprintMismatch();
        TestUnboundRuntimeGrant();
        Console.WriteLine($"Shared app-key vectors: {count} passed; binding defaults passed");
    }

    private static Fingerprint? NativeFingerprintOrNull(AppKey app)
    {
        try { return new Fingerprint(DeviceIdentity.NativeFingerprint(app.ApplicationId, app.EnvironmentId), DeviceIdentity.Provider); }
        catch (OrbitException error) when (error.Error == OrbitError.Denied && error.Code == "device_identity_unavailable") { return null; }
    }

    private static void TestSavedFingerprintMismatch()
    {
        var scope = new InstalledScope("https://orbit.example.test", "https://orbit.example.test", "app", "test");
        var record = new InstalledRecord(InstalledCodec.Sdk, 2, "private_file", scope,
            new InstalledIdentity("installation_123456", new string('a', 64), "machine_v1"),
            0, null, null, null);
        var bytes = InstalledCodec.Encode(record);
        try
        {
            try
            {
                _ = InstalledCodec.Decode(bytes, scope, "private_file", new string('b', 64), "machine_v1");
                throw new InvalidOperationException("saved machine identity mismatch was accepted");
            }
            catch (OrbitException error) when (error.Error == OrbitError.Storage) { }
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void TestUnboundRuntimeGrant()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes("contracts/sdk/grants.json"));
        var root = document.RootElement;
        var item = root.GetProperty("cases").EnumerateArray().First(caseItem =>
            caseItem.GetProperty("name").GetString() == "strict-valid");
        var expected = root.GetProperty("expected");
        var config = new OrbitConfig(JsonWire.String(expected, "application"), JsonWire.String(expected, "environment"),
            JsonWire.String(expected, "issuer"));
        var fingerprint = new Device(JsonWire.String(expected, "installation"), new string('a', 64), "machine_v1");
        var keys = GrantKeys.Parse(root.GetProperty("jwks"));
        var runtimeExpected = new GrantExpected(config, fingerprint, null, JsonWire.String(expected, "activation"),
            JsonWire.OptionalInteger(expected, "credential_expires_at"), JsonWire.OptionalInteger(expected, "licence_expires_at"),
            JsonWire.Integer(expected, "now"), AllowUnboundFingerprint: true, ExpectedBindingMode: "none");
        _ = keys.VerifyAsync(item.GetProperty("token").GetString()!, runtimeExpected).GetAwaiter().GetResult();
        ExpectInvalidGrant(() => keys.VerifyAsync(item.GetProperty("token").GetString()!, runtimeExpected with
        { AllowUnboundFingerprint = false }).GetAwaiter().GetResult());
        ExpectInvalidGrant(() => keys.VerifyAsync(item.GetProperty("token").GetString()!, runtimeExpected with
        { ExpectedBindingMode = "hwid" }).GetAwaiter().GetResult());
    }

    private static void ExpectInvalidGrant(Action action)
    {
        try { action(); }
        catch (OrbitException error) when (error.Error == OrbitError.InvalidResponse) { return; }
        throw new InvalidOperationException("invalid runtime grant binding was accepted");
    }

    private static void ExpectConfiguration(Action action)
    {
        try { action(); }
        catch (OrbitException error) when (error.Error == OrbitError.Configuration) { return; }
        throw new InvalidOperationException("invalid input was accepted");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
