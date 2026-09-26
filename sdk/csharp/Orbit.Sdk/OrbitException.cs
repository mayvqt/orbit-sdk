namespace Orbit.Sdk;

public enum OrbitError
{
    Configuration, Cancelled, Transient, Denied, InvalidResponse, TransportSecurity,
    ReauthenticationRequired, StaleResponse, Storage, ClockUncertain
}

/// <summary>Contains only safe error classification, never server messages or bearer material.</summary>
public sealed class OrbitException : Exception
{
    public OrbitError Error { get; }
    public string? Code { get; }
    /// <summary>Validated server correlation reference; absent for local failures.</summary>
    public string? RequestId { get; }

    public OrbitException(OrbitError error, string? code = null, string? requestId = null) : base(Guidance(error, code))
    {
        Error = error;
        Code = code;
        RequestId = (error is OrbitError.Denied or OrbitError.Transient) && ValidRequestId(requestId) ? requestId : null;
    }

    internal static bool ValidRequestId(string? value) => value is { Length: >= 1 and <= 64 } &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');
    internal static bool ValidCode(string? value) => value is { Length: >= 1 and <= 128 } &&
        value.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_');

    private static string Guidance(OrbitError error, string? code)
    {
        if (error is OrbitError.Denied or OrbitError.Transient)
        {
            var guidance = code switch
            {
                "invalid_credentials" or "credential_expired" or "credential_revoked" or "reauthentication_required" =>
                    "Authenticate again with your licence key or customer account.",
                "session_expired" or "session_revoked" => "Sign in again to continue.",
                "licence_expired" => "Your licence has expired. Contact application support to renew it.",
                "licence_suspended" => "Your licence is suspended. Contact application support.",
                "licence_revoked" => "Your licence was revoked. Contact application support.",
                "device_limit_reached" => "The device limit is reached. Release an existing device or contact application support.",
                "device_mismatch" or "device_identity_unavailable" => "This device could not be verified. Contact application support.",
                "reset_cooldown" => "Device changes are temporarily limited. Wait before trying again.",
                "application_maintenance" => "The application is under maintenance. Try again after maintenance ends.",
                "rate_limited" => "Too many requests. Wait before trying again.",
                "service_unavailable" => "Orbit is temporarily unavailable. Try again later.",
                _ => null
            };
            if (guidance != null) return guidance;
        }
        return error switch
        {
            OrbitError.Configuration => "Invalid Orbit configuration",
            OrbitError.Cancelled => "Operation cancelled",
            OrbitError.Transient => "Orbit is temporarily unreachable. Try again later.",
            OrbitError.Denied => "Orbit denied access. Contact application support.",
            OrbitError.InvalidResponse => "Orbit response verification failed",
            OrbitError.TransportSecurity => "Secure connection failed",
            OrbitError.ReauthenticationRequired => "Fresh licence authentication is required",
            OrbitError.StaleResponse => "Discarded a superseded response",
            OrbitError.Storage => code switch
            {
                "installation_in_use" => "This installation is already open. Share its client or close the other process.",
                "pending_activation" => "An activation is unresolved. Retry the same input or deliberately resolve it with Logout.",
                "pending_activation_expired" => "Activation recovery expired. Deliberately resolve it before trying again.",
                _ => "Credential storage failed. Preserve the state directory and contact application support."
            },
            OrbitError.ClockUncertain => "Online clock validation is required",
            _ => "Orbit operation failed"
        };
    }

    internal static void CheckCancellation(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested) throw new OrbitException(OrbitError.Cancelled);
    }
}
