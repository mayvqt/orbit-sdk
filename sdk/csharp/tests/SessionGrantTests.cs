using System.Collections.ObjectModel;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Orbit.Sdk;

internal static class SessionGrantTests
{
    internal static async Task<int> RunAsync(string path)
    {
        var root = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
        if (root["format_version"]!.GetValue<int>() != 1 || root["cases"] is not JsonArray cases || cases.Count != 184)
            throw new InvalidOperationException("Session corpus is missing cases");
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
                var expected = Expected(JsonSerializer.SerializeToElement(context));
                var keys = SessionKeys.Parse(JsonSerializer.SerializeToElement(test["jwks"] ?? root["jwks"]),
                    context["key_environment"]!.GetValue<string>());
                var grant = keys.Verify(test["token"]!.GetValue<string>(), expected);
                if (grant.SessionId != expected.SessionId || grant.Sequence != expected.Sequence ||
                    grant.ExpiresAt <= expected.Grant.Now || grant.ExpiresAt - grant.IssuedAt > 120)
                    throw new InvalidOperationException("Invalid verified session metadata");
                accepted = true;
            }
            catch (OrbitException error) when (error.Error == OrbitError.InvalidResponse) { }
            if (accepted != test["valid"]!.GetValue<bool>())
                throw new InvalidOperationException($"Session vector failed: {test["name"]!.GetValue<string>()}");
            passed++;
        }
        await BoundariesAsync(root, path);
        Console.WriteLine($"Shared session vectors: {passed} passed; key bounds, metadata, purpose and concurrent checks pass.");
        return 0;
    }

    private static SessionExpected Expected(JsonElement context)
    {
        var config = new OrbitConfig(JsonWire.String(context, "application"), JsonWire.String(context, "environment"),
            JsonWire.String(context, "issuer"));
        var device = new Device(JsonWire.String(context, "installation"), JsonWire.OptionalString(context, "fingerprint"),
            JsonWire.OptionalString(context, "fingerprint_provider"));
        var grant = new GrantExpected(config, device, JsonWire.OptionalString(context, "licence"),
            JsonWire.String(context, "activation"), JsonWire.OptionalInteger(context, "credential_expires_at"),
            JsonWire.OptionalInteger(context, "licence_expires_at"), JsonWire.Integer(context, "now"),
            context.TryGetProperty("allow_unbound_fingerprint", out var optional) && JsonWire.Bool(optional));
        return new SessionExpected(grant, JsonWire.String(context, "session_id"), JsonWire.Integer(context, "sequence"));
    }

    private static async Task BoundariesAsync(JsonObject root, string path)
    {
        var expected = Expected(JsonSerializer.SerializeToElement(root["expected"]));
        var token = root["cases"]![0]!["token"]!.GetValue<string>();
        var rawKeys = JsonSerializer.SerializeToElement(root["jwks"]);
        var encoded = rawKeys.GetRawText();
        var exact = encoded + new string(' ', 16384 - Encoding.UTF8.GetByteCount(encoded));
        var bytes = Encoding.UTF8.GetBytes(exact);
        var keys = SessionKeys.Parse(bytes, "test");
        Array.Fill(bytes, (byte)'x');
        var grant = keys.Verify(token, expected);
        if (grant.ToString() != "SessionGrant(<redacted>)" || grant.Entitlements is not ReadOnlyDictionary<string, bool> immutable)
            throw new InvalidOperationException("Mutable or unredacted session metadata");
        try { ((IDictionary<string, bool>)immutable)["export"] = false; throw new InvalidOperationException("Mutation accepted"); }
        catch (NotSupportedException) { }
        foreach (var malformed in new[] { exact + " ", encoded[..^1] + ",\"keys\":[]}" })
            Reject(() => SessionKeys.Parse(Encoding.UTF8.GetBytes(malformed), "test"), "invalid_session_keys");
        Reject(() => keys.Verify(token + "private", expected), "invalid_session_grant");
        foreach (var result in await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(() => keys.Verify(token, expected)))))
            if (result.Sequence != 1) throw new InvalidOperationException("Concurrent session verification changed metadata");

        try
        {
            _ = await GrantKeys.Parse(rawKeys).VerifyAsync(token, expected.Grant);
            throw new InvalidOperationException("Ordinary verifier accepted a session");
        }
        catch (OrbitException error) when (error.Error == OrbitError.InvalidResponse) { }
        var directory = Path.GetDirectoryName(path)!;
        var offline = JsonNode.Parse(File.ReadAllText(Path.Combine(directory, "offline-files.json")))!.AsObject();
        var offlineContext = offline["expected"]!.AsObject();
        var app = AppKey.Parse(offlineContext["app_key"]!.GetValue<string>());
        var offlineExpected = new OfflineExpected(app, new Device(offlineContext["installation_id"]!.GetValue<string>()),
            offlineContext["now"]!.GetValue<long>());
        Reject(() => OfflineKeys.Parse(JsonSerializer.SerializeToElement(offline["jwks"]), app.Environment).Verify(token, offlineExpected),
            "invalid_offline_file");
        var downloads = JsonNode.Parse(File.ReadAllText(Path.Combine(directory, "download-tickets.json")))!.AsObject();
        var downloadContext = downloads["expected"]!.AsObject();
        var verifier = new DownloadTicketVerifier(downloadContext["app_key"]!.GetValue<string>(),
            downloadContext["endpoint"]!.GetValue<string>(), Encoding.UTF8.GetBytes(downloads["jwks"]!.ToJsonString()));
        try
        {
            _ = verifier.Verify(token, DateTimeOffset.FromUnixTimeSeconds(downloadContext["now"]!.GetValue<long>()));
            throw new InvalidOperationException("Download verifier accepted a session");
        }
        catch (OrbitException error) when (error.Error == OrbitError.Denied && error.Code == "invalid_download_ticket") { }
    }

    private static void Reject<T>(Func<T> action, string code)
    {
        try { _ = action(); throw new InvalidOperationException("Invalid session input accepted"); }
        catch (OrbitException error) when (error.Error == OrbitError.InvalidResponse && error.Code == code) { }
    }
}
