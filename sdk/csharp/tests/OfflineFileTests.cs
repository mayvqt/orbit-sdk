using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Orbit.Sdk;

internal static class OfflineFileTests
{
    internal static int Run(string path)
    {
        var root = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        if (root["format_version"]!.GetValue<int>() != 1 || root["cases"] is not JsonArray cases || cases.Count == 0)
            throw new InvalidOperationException("Offline corpus is missing cases");
        var passed = 0;
        foreach (var entry in cases)
        {
            var test = entry!.AsObject();
            var context = root["expected"]!.DeepClone().AsObject();
            if (test["expected"] is JsonObject overrides)
                foreach (var property in overrides) context[property.Key] = property.Value?.DeepClone();
            var accepted = false;
            try
            {
                var app = AppKey.Parse(context["app_key"]!.GetValue<string>());
                var expected = new OfflineExpected(app,
                    new Device(context["installation_id"]!.GetValue<string>(), context["fingerprint"]?.GetValue<string>(),
                        context["fingerprint_provider"]?.GetValue<string>()), context["now"]!.GetValue<long>(),
                    context["minimum_sequence"]!.GetValue<long>());
                var keys = OfflineKeys.Parse(JsonSerializer.SerializeToElement(test["jwks"] ?? root["jwks"]), app.Environment);
                var file = keys.Verify(test["token"]!.GetValue<string>(), expected);
                if (!file.Entitlements["export"] || file.ExpiresAt <= expected.Now ||
                    file.ToString().Contains(file.Token, StringComparison.Ordinal))
                    throw new InvalidOperationException("Invalid verified metadata");
                if (file.Entitlements is not ReadOnlyDictionary<string, bool> immutable)
                    throw new InvalidOperationException("Mutable offline entitlements");
                try { ((IDictionary<string, bool>)immutable)["export"] = false; throw new InvalidOperationException("Mutation accepted"); }
                catch (NotSupportedException) { }
                accepted = true;
            }
            catch (OrbitException exception) when (exception.Error == OrbitError.InvalidResponse) { }
            if (accepted != test["valid"]!.GetValue<bool>())
                throw new InvalidOperationException($"Offline vector failed: {test["name"]!.GetValue<string>()}");
            passed++;
        }
        CanonicalClaims(root, path);
        Console.WriteLine($"Shared offline vectors: {passed} passed; canonical claims and strict key checks pass.");
        return 0;
    }

    private static void CanonicalClaims(JsonObject root, string path)
    {
        var context = root["expected"]!.AsObject();
        var app = AppKey.Parse(context["app_key"]!.GetValue<string>());
        var expected = new OfflineExpected(app, new Device(context["installation_id"]!.GetValue<string>()), context["now"]!.GetValue<long>());
        var rawKeys = JsonSerializer.SerializeToElement(root["jwks"]);
        var keys = OfflineKeys.Parse(rawKeys, app.Environment);
        var original = root["cases"]![0]!["token"]!.GetValue<string>();
        var first = keys.Verify(original, expected);
        // Independently obtained from the Python verifier for this shared
        // fixture: SHA-256 of sorted, normalized UTF-8 claims.
        if (first.ContentDigest != "8aed1c86dab86f56c744802ee68650041ddc12e8d56bb6d73c2f40049424740a")
            throw new InvalidOperationException("Cross-SDK canonical claims digest differs");
        var parts = original.Split('.');
        var claims = JsonNode.Parse(JsonWire.DecodeBase64(parts[1]))!.AsObject();
        var reordered = new JsonObject();
        foreach (var property in claims.Reverse()) reordered[property.Key] = property.Value?.DeepClone();
        var message = parts[0] + "." + JsonWire.EncodeBase64(Encoding.UTF8.GetBytes(reordered.ToJsonString(new JsonSerializerOptions { WriteIndented = true })));
        var fixture = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(path)!, "../../sdk/rust/tests/fixtures/es256-test-private.pem"));
        using var signer = ECDsa.Create();
        signer.ImportFromPem(File.ReadAllText(fixture));
        var signature = signer.SignData(Encoding.ASCII.GetBytes(message), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var second = keys.Verify(message + "." + JsonWire.EncodeBase64(signature), expected);
        if (first.ContentDigest != second.ContentDigest || first.IssuanceId != second.IssuanceId || first.Sequence != second.Sequence)
            throw new InvalidOperationException("Equivalent signed claims changed renewal identity");
        foreach (var malformed in new[]
        {
            rawKeys.GetRawText()[..^1] + ",\"keys\":[]}",
            "{\"keys\":[]}",
            rawKeys.GetRawText() + new string(' ', 16384)
        })
        {
            try
            {
                _ = OfflineKeys.Parse(Encoding.UTF8.GetBytes(malformed), app.Environment);
                throw new InvalidOperationException("Invalid offline keys accepted");
            }
            catch (OrbitException exception) when (exception.Error == OrbitError.InvalidResponse) { }
        }
        var exactBound = rawKeys.GetRawText() + new string(' ', OfflineKeys.MaximumFileBytes - Encoding.UTF8.GetByteCount(rawKeys.GetRawText()));
        _ = OfflineKeys.Parse(Encoding.UTF8.GetBytes(exactBound), app.Environment).Verify(original, expected);
    }
}
