using System.Text.Json;
using Orbit.Sdk;

internal static class CredentialRetentionTests
{
    internal static void Run()
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes("contracts/sdk/credential-retention.json"));
        foreach (var item in document.RootElement.GetProperty("denials").EnumerateArray())
        {
            var code = item.GetProperty("code").GetString()!;
            var denied = new OrbitException(OrbitError.Denied, code);
            if (denied.DiscardsCredential != item.GetProperty("discard_credential").GetBoolean())
                throw new InvalidOperationException($"credential-retention vector mismatch: {code}");
        }
        if (new OrbitException(OrbitError.Transient, "licence_revoked").DiscardsCredential)
            throw new InvalidOperationException("transient failure discarded the credential");
    }
}
