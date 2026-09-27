using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Orbit.Sdk;

internal static class DownloadTicketTests
{
    internal static int Run(string path)
    {
        var root = JsonNode.Parse(File.ReadAllBytes(path))!.AsObject();
        if (root["format_version"]!.GetValue<int>() != 1 || root["cases"]!.AsArray().Count != 110)
            throw new InvalidOperationException("Unexpected download-ticket corpus.");
        var passed = 0;
        foreach (var item in root["cases"]!.AsArray())
        {
            var sample = item!.AsObject();
            var expected = root["expected"]!.DeepClone().AsObject();
            if (sample["expected"] is JsonObject overrides)
                foreach (var field in overrides) expected[field.Key] = field.Value?.DeepClone();
            var valid = false;
            try
            {
                var verifier = new DownloadTicketVerifier(expected["app_key"]!.GetValue<string>(), expected["endpoint"]!.GetValue<string>(),
                    JsonSerializer.SerializeToUtf8Bytes(sample["jwks"] ?? root["jwks"]));
                _ = verifier.Verify(sample["token"]!.GetValue<string>(), DateTimeOffset.FromUnixTimeSeconds(expected["now"]!.GetValue<long>()));
                valid = true;
            }
            catch (OrbitException) { }
            if (valid != sample["valid"]!.GetValue<bool>())
                throw new InvalidOperationException($"Download ticket failed: {sample["name"]!.GetValue<string>()}");
            passed++;
        }

        var appKey = root["expected"]!["app_key"]!.GetValue<string>();
        var endpoint = root["expected"]!["endpoint"]!.GetValue<string>();
        var keys = JsonSerializer.SerializeToUtf8Bytes(root["jwks"]);
        var token = root["cases"]![0]!["token"]!.GetValue<string>();
        var now = DateTimeOffset.FromUnixTimeSeconds(root["expected"]!["now"]!.GetValue<long>());
        var copiedKeys = new DownloadTicketVerifier(appKey, endpoint, keys);
        Array.Fill(keys, (byte)'!');
        var verified = copiedKeys.Verify(token, now);
        if (verified.ToString() != "DownloadTicket(<redacted>)" || verified.ByteLength <= 0 || verified.ExpiresAt <= now)
            throw new InvalidOperationException("Download metadata shape or redaction failed.");
        _ = copiedKeys.Verify(token, verified.ExpiresAt.AddTicks(-1));
        Expect(() => copiedKeys.Verify(token, verified.ExpiresAt), OrbitError.Denied, "invalid_download_ticket");
        Expect(() => copiedKeys.Verify(token, now.AddSeconds(-30).AddTicks(-1)), OrbitError.Denied, "invalid_download_ticket");

        keys = JsonSerializer.SerializeToUtf8Bytes(root["jwks"]);
        var boundedKeys = new byte[16384];
        Array.Fill(boundedKeys, (byte)' ');
        keys.CopyTo(boundedKeys, 0);
        _ = new DownloadTicketVerifier(appKey, endpoint, boundedKeys).Verify(token, now);
        byte[] oversizedKeys = [.. boundedKeys, (byte)' '];
        Expect(() => new DownloadTicketVerifier(appKey, endpoint, oversizedKeys),
            OrbitError.Configuration, "invalid_download_keys");
        var duplicate = Encoding.UTF8.GetBytes("{\"keys\":[]," + Encoding.UTF8.GetString(keys)[1..]);
        Expect(() => new DownloadTicketVerifier(appKey, endpoint, duplicate), OrbitError.Configuration, "invalid_download_keys");
        foreach (var invalid in new[] { "http://host/file", "https://user:password@host/file", "https://@host/file",
            "https://host:/file", "https://%64ownloads.example.test/file", "https://host:65536/file",
            "https://[::1]:/file", "https://[::1]suffix/file", "https://host/file?", "https://host/file#", "https://host/\\file",
            "https://host/f ile", "https://host/<file>", "https://host/\"file\"", "https://host/{file}", "https://host/雪", "https://host/%", "https://host/%aZ", "https://host:0/file" })
            Expect(() => new DownloadTicketVerifier(appKey, invalid, keys), OrbitError.Configuration, "invalid_download_endpoint");
        _ = new DownloadTicketVerifier(appKey, "https://host:00080/file%2Fname", keys);
        Console.WriteLine($"Shared download-ticket vectors: {passed} passed; key bounds/copy, endpoints, redaction and exact clock boundaries passed.");
        return 0;
    }

    private static void Expect(Action action, OrbitError kind, string code)
    {
        try { action(); }
        catch (OrbitException error) when (error.Error == kind && error.Code == code) { return; }
        throw new InvalidOperationException("Expected a scoped download verification failure.");
    }
}
