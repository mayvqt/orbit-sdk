using System.Text.Json;
using System.Text.Json.Nodes;
using Orbit.Sdk;

if (args is ["--storage-child", var action, var directory]) return WindowsStorageTests.Child(action, directory);

if (args is ["--secret-storage-child", var secretAction, var secretDirectory]) return NativeSecretServiceTests.Child(secretAction, secretDirectory);

if (args.Length >= 2 && args[0] == "--secret-tool-fixture") return await SecretServiceTests.HelperChild(args[1..]);

if (args is ["--native-storage"]) return await NativeSecretServiceTests.RunAsync();

if (args is ["--clock-suspend"]) return NativeClockTests.RunSuspend();

if (args is ["--grant-suspend"]) return await NativeClockTests.RunGrantSuspendAsync();

if (args is ["--native-device"]) return DeviceIdentityTests.RunNative();

if (args is ["--native-protection"])
{
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
    try
    {
        await DataProtectionTests.RunAsync(deadline.Token);
        Console.WriteLine("PASS: native current-user protection and corruption boundaries.");
        return 0;
    }
    catch (Exception)
    {
        Console.Error.WriteLine("FAIL: native current-user protection; a Windows password logon is required.");
        return 1;
    }
}

if (args is ["--installed"]) return await InstalledTests.RunAsync();

if (args is ["--security"]) return await SecurityTests.RunAsync();

if (args.Length != 1)
{
    Console.Error.WriteLine("Usage: Orbit.Sdk.Tests PATH_TO_SHARED_GRANTS_JSON | --security | --installed | --native-device | --native-protection | --native-storage | --clock-suspend | --grant-suspend");
    return 2;
}

var root = JsonNode.Parse(await File.ReadAllTextAsync(args[0]))!.AsObject();
if (root["format_version"] is not JsonValue version || !version.TryGetValue<int>(out var format) || format != 1 ||
    root["cases"] is not JsonArray cases || cases.Count == 0)
{
    Console.Error.WriteLine("Shared grants require format_version 1 and nonempty cases");
    return 2;
}
var passed = 0;
var failed = 0;
foreach (var entry in cases)
{
    var test = entry!.AsObject();
    var expected = root["expected"]!.DeepClone().AsObject();
    if (test["expected"] is JsonObject overrides)
        foreach (var item in overrides) expected[item.Key] = item.Value?.DeepClone();
    var json = JsonSerializer.SerializeToElement(expected);
    var valid = false;
    try
    {
        var keys = GrantKeys.Parse(JsonSerializer.SerializeToElement(test["jwks"] ?? root["jwks"]));
        var config = new OrbitConfig(JsonWire.String(json, "application"), JsonWire.String(json, "environment"), JsonWire.String(json, "issuer"));
        var device = new Device(JsonWire.String(json, "installation"), JsonWire.OptionalString(json, "fingerprint"),
            JsonWire.OptionalString(json, "fingerprint_provider"));
        var binding = new GrantExpected(config, device, JsonWire.OptionalString(json, "licence"), JsonWire.String(json, "activation"),
            JsonWire.OptionalInteger(json, "credential_expires_at"), JsonWire.OptionalInteger(json, "licence_expires_at"), JsonWire.Integer(json, "now"));
        _ = await keys.VerifyAsync(test["token"]!.GetValue<string>(), binding);
        valid = true;
    }
    catch (OrbitException error) when (error.Error == OrbitError.InvalidResponse) { }
    if (valid == test["valid"]!.GetValue<bool>()) passed++;
    else
    {
        failed++;
        Console.Error.WriteLine($"FAIL: {test["name"]!.GetValue<string>()}");
    }
}
Console.WriteLine($"Shared grant vectors: {passed} passed, {failed} failed");
return failed == 0 ? 0 : 1;
