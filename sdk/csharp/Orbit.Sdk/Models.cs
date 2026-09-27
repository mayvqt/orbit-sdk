using System.Collections.ObjectModel;
using System.Security.Cryptography;

namespace Orbit.Sdk;

internal sealed record OrbitConfig(string ApplicationId, string EnvironmentId, string Issuer)
{
    internal void Validate(Device device)
    {
        if (!JsonWire.Opaque(ApplicationId) || !JsonWire.Opaque(EnvironmentId) ||
            string.IsNullOrEmpty(Issuer) || Issuer.Length > 2048 ||
            !JsonWire.Opaque(device.InstallationId) || device.InstallationId.Length < 16 ||
            (device.Fingerprint == null) != (device.FingerprintProvider == null) ||
            (device.Fingerprint != null && (device.Fingerprint.Length != 64 ||
                !device.Fingerprint.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'))) ||
            (device.FingerprintProvider != null && !ValidProvider(device.FingerprintProvider)))
            throw new OrbitException(OrbitError.Configuration);
    }

    private static bool ValidProvider(string value) => value == "machine_v1" ||
        (value.StartsWith("custom:", StringComparison.Ordinal) && value.Length is > 7 and <= 55 &&
         value[7..].All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-' or '.'));
}

/// <summary>Public application and device scope used to connect an Orbit client.</summary>
internal sealed record Device(string InstallationId, string? Fingerprint = null, string? FingerprintProvider = null)
{
    public static Device NewInstallation() => new(JsonWire.EncodeBase64(RandomNumberGenerator.GetBytes(24)));
}

// Retained only for deterministic SDK-internal fixtures. The public API accepts AppKey.
internal sealed record OrbitSetup(string ApiOrigin, string ApplicationId, string EnvironmentId,
    string Issuer, string InstallationId);

public enum Access { Denied, Online, Offline, RefreshRequired, Expired }

/// <summary>Informational state. Call RequireAccessAsync immediately before each protected operation.</summary>
public sealed record Snapshot(
    Access Access,
    IReadOnlyDictionary<string, bool> Entitlements,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? NextCheckAt,
    DateTimeOffset? CredentialExpiresAt,
    bool ReauthenticationRequired,
    bool OfflineAllowed,
    TimeSpan RemainingOffline)
{
    public int? PolicyVersion { get; init; }
    public bool OfflineFileMode { get; init; }
    public bool HasFeature(string feature) => Entitlements.TryGetValue(feature, out var enabled) && enabled;
    internal static readonly IReadOnlyDictionary<string, bool> EmptyEntitlements =
        new ReadOnlyDictionary<string, bool>(new Dictionary<string, bool>());

    internal static DateTimeOffset? FromUnixSeconds(long? value) =>
        value is { } seconds and > 0 ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null;
}
