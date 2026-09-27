using System.Text.Json;
using Orbit.Sdk;

internal static class AppVersionTests
{
    internal static void Run()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes("contracts/sdk/app-versions.json"));
        var root = document.RootElement;
        Require(root.GetProperty("format_version").GetInt32() == 1, "unexpected app-version vector version");
        foreach (var item in root.GetProperty("app_versions").EnumerateArray())
        {
            var value = item.GetProperty("value").GetString()!;
            var valid = item.GetProperty("valid").GetBoolean();
            Require(AppVersion.Valid(value) == valid, $"app-version vector mismatch: {value}");
            try
            {
                _ = AppVersion.Configured(value);
                Require(valid, $"configured an invalid app version: {value}");
            }
            catch (OrbitException error) when (error.Error == OrbitError.Configuration)
            {
                Require(!valid, $"rejected a valid app version: {value}");
            }
        }
        foreach (var item in root.GetProperty("client_headers").EnumerateArray())
        {
            var header = AppVersion.FormatClientHeader(item.GetProperty("language").GetString()!,
                item.GetProperty("sdk_version").GetString()!, item.GetProperty("platform").GetString()!);
            var expected = item.GetProperty("header");
            Require(expected.ValueKind == JsonValueKind.Null ? header == null : header == expected.GetString(),
                $"client header vector mismatch: {item}");
        }
        var own = AppVersion.ClientHeader;
        var open = own.IndexOf(" (", StringComparison.Ordinal);
        Require(own.StartsWith("csharp/" + AppVersion.SdkVersion() + " (", StringComparison.Ordinal) &&
            AppVersion.SdkVersion().StartsWith("0.4.0", StringComparison.Ordinal) &&
            AppVersion.FormatClientHeader("csharp", AppVersion.SdkVersion(), own[(open + 2)..^1]) == own,
            $"unexpected SDK client header: {own}");
        foreach (var item in root.GetProperty("update_available").EnumerateArray())
        {
            var reply = item.TryGetProperty("value", out var value)
                ? $"{{\"activation_id\":\"activation\",\"update_available\":{value.GetRawText()}}}"
                : "{\"activation_id\":\"activation\"}";
            using var parsed = JsonDocument.Parse(reply);
            try
            {
                var version = AppVersion.UpdateHint(parsed.RootElement);
                Require(item.GetProperty("valid").GetBoolean(), $"accepted update hint: {item.GetProperty("name").GetString()}");
                var expected = item.GetProperty("version");
                Require(version == (expected.ValueKind == JsonValueKind.Null ? null : expected.GetString()),
                    $"update hint mismatch: {item.GetProperty("name").GetString()}");
            }
            catch (OrbitException error) when (error.Error == OrbitError.InvalidResponse)
            {
                Require(!item.GetProperty("valid").GetBoolean(), $"rejected update hint: {item.GetProperty("name").GetString()}");
            }
        }
        var denial = new OrbitException(OrbitError.AppVersionUnsupported, "app_version_unsupported", "request_1");
        Require(denial.RequestId == "request_1" && denial.Message.Contains("Update the application", StringComparison.Ordinal),
            "app-version denial must keep its request ID and guidance");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
