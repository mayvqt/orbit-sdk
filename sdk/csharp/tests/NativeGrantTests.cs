using System.Text.Json;
using System.Text.Json.Nodes;
using Orbit.Sdk;

internal static class NativeGrantTests
{
    internal static async Task RunAsync(JsonObject root)
    {
        var sample = root["cases"]!.AsArray().Select(item => item!.AsObject())
            .First(item => item["valid"]!.GetValue<bool>() && item["jwks"] == null && item["expected"] == null);
        var token = sample["token"]!.GetValue<string>();
        var json = JsonSerializer.SerializeToElement(root["expected"]);
        var expected = new GrantExpected(
            new OrbitConfig(JsonWire.String(json, "application"), JsonWire.String(json, "environment"), JsonWire.String(json, "issuer")),
            new Device(JsonWire.String(json, "installation"), JsonWire.OptionalString(json, "fingerprint"),
                JsonWire.OptionalString(json, "fingerprint_provider")),
            JsonWire.OptionalString(json, "licence"), JsonWire.String(json, "activation"),
            JsonWire.OptionalInteger(json, "credential_expires_at"), JsonWire.OptionalInteger(json, "licence_expires_at"),
            JsonWire.Integer(json, "now"));
        var keys = GrantKeys.Parse(JsonSerializer.SerializeToElement(root["jwks"]));
        var exported = GrantKeys.Parse(keys.Export(token));
        var original = await keys.VerifyAsync(token, expected);
        var restored = await exported.VerifyAsync(token, expected);
        if (restored.LicenceId != original.LicenceId || restored.ExpiresAt != original.ExpiresAt)
            throw new InvalidOperationException("Exported public key changed verification.");

        await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(async () =>
        {
            var verified = await keys.VerifyAsync(token, expected);
            if (verified.LicenceId != original.LicenceId) throw new InvalidOperationException("Concurrent verification changed claims.");
        })));

        var invalidRetained = root["jwks"]!.DeepClone().AsObject();
        var entry = invalidRetained["keys"]![0]!.DeepClone().AsObject();
        entry["kid"] = "invalid-retained-point";
        entry["x"] = JsonWire.EncodeBase64(new byte[32]);
        entry["y"] = JsonWire.EncodeBase64(new byte[32]);
        invalidRetained["keys"]!.AsArray().Add(entry);
        try
        {
            _ = GrantKeys.Parse(JsonSerializer.SerializeToElement(invalidRetained));
            throw new InvalidOperationException("An invalid retained EC point was accepted.");
        }
        catch (OrbitException error) when (error.Error == OrbitError.InvalidResponse) { }
        Console.WriteLine("Native grant checks: export/reimport, concurrent verification and retained-point validation passed.");
    }
}
