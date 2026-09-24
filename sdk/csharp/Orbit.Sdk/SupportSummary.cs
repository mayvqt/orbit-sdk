using System.Text.Json.Serialization;

namespace Orbit.Sdk;

/// <summary>Copyable diagnostic metadata, never authentication or authorization proof.</summary>
public sealed record SupportSummary(
    [property: JsonPropertyName("application_id")] string ApplicationId,
    [property: JsonPropertyName("environment_id")] string EnvironmentId,
    [property: JsonPropertyName("code")] string Code,
    [property: JsonPropertyName("request_id")] string? RequestId,
    [property: JsonPropertyName("timestamp")] long? Timestamp);

public sealed partial class OrbitClient
{
    /// <summary>
    /// Returns public scope and safe metadata for the supplied error without
    /// reading account, access, device or storage state or contacting Orbit.
    /// Timestamp is local Unix seconds, nullable when unavailable; not an access clock.
    /// </summary>
    public SupportSummary SupportSummary(OrbitException error)
    {
        var code = error.Error switch
        {
            OrbitError.Configuration => "configuration",
            OrbitError.Cancelled => "cancelled",
            OrbitError.Transient => "transient",
            OrbitError.Denied => "denied",
            OrbitError.InvalidResponse => "invalid_response",
            OrbitError.TransportSecurity => "transport_security",
            OrbitError.ReauthenticationRequired => "reauthentication_required",
            OrbitError.StaleResponse => "stale_response",
            OrbitError.Storage => "storage",
            OrbitError.ClockUncertain => "clock_uncertain",
            _ => "unknown_error"
        };
        string? requestId = null;
        if (error.Error is OrbitError.Denied or OrbitError.Transient)
        {
            if (OrbitException.ValidCode(error.Code)) code = error.Code!;
            if (OrbitException.ValidRequestId(error.RequestId)) requestId = error.RequestId;
        }
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return new SupportSummary(config.ApplicationId, config.EnvironmentId, code, requestId, now >= 0 ? now : null);
    }
}
