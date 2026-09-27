// Package orbit implements the Orbit v1 installed-client protocol.
// Call RequireAccess before every protected operation.
package orbit

import "fmt"

// ErrorKind identifies an error without exposing server text or credentials.
type ErrorKind string

const (
	Configuration            ErrorKind = "configuration"
	Cancelled                ErrorKind = "cancelled"
	Transient                ErrorKind = "transient"
	Denied                   ErrorKind = "denied"
	NotActivated             ErrorKind = "not_activated"
	FeatureUnavailable       ErrorKind = "feature_unavailable"
	InvalidResponse          ErrorKind = "invalid_response"
	TransportSecurity        ErrorKind = "transport_security"
	ReauthenticationRequired ErrorKind = "reauthentication_required"
	StaleResponse            ErrorKind = "stale_response"
	StorageFailure           ErrorKind = "storage"
	ClockUncertain           ErrorKind = "clock_uncertain"
)

// Error contains classification and validated HTTP error metadata, never response text.
// RequestID is empty for local failures. SupportSummary validates caller-created errors too.
type Error struct {
	Kind      ErrorKind
	Code      string
	RequestID string
}

func (e *Error) Error() string {
	if e == nil {
		return "Orbit operation failed"
	}
	if e.Kind == Denied || e.Kind == Transient {
		if guidance := errorGuidance(e.Code); guidance != "" {
			return guidance
		}
	}
	switch e.Kind {
	case Configuration:
		return "Invalid Orbit configuration"
	case Cancelled:
		if e.Code == "closed" {
			return "The Orbit client is closed"
		}
		return "Operation cancelled"
	case Transient:
		return "Orbit is temporarily unreachable. Try again later."
	case Denied:
		return "Orbit denied access. Contact application support."
	case NotActivated:
		return "Activate a licence to continue."
	case FeatureUnavailable:
		return "This licence does not include the requested feature."
	case InvalidResponse:
		return "Orbit response verification failed"
	case TransportSecurity:
		return "Secure connection failed"
	case ReauthenticationRequired:
		return "Fresh licence authentication is required"
	case StaleResponse:
		return "Discarded a superseded response"
	case StorageFailure:
		switch e.Code {
		case "installation_in_use":
			return "This installation is already open. Share the existing client or close the other process."
		case "pending_activation":
			return "An activation is unresolved. Retry the same input or deliberately resolve it with Logout."
		case "pending_activation_expired":
			return "Activation recovery expired. Deliberately resolve the pending activation before retrying."
		case "macos_cgo_required":
			return "macOS installed clients require cgo and the Xcode Command Line Tools."
		}
		return "Credential storage failed. Preserve the state directory and contact application support."
	case ClockUncertain:
		return "Online clock validation is required"
	default:
		return "Orbit operation failed"
	}
}

// Format never echoes caller-supplied fields, including with detailed fmt verbs.
func (e Error) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(e.Error())) }

func errorGuidance(code string) string {
	switch code {
	case "invalid_credentials", "credential_expired", "credential_revoked", "reauthentication_required":
		return "Authenticate again with your licence key or customer account."
	case "session_expired", "session_revoked":
		return "Sign in again to continue."
	case "licence_expired":
		return "Your licence has expired. Contact application support to renew it."
	case "offline_file_expired":
		return "Your offline licence file has expired. Request a renewed file from application support."
	case "licence_suspended":
		return "Your licence is suspended. Contact application support."
	case "licence_revoked":
		return "Your licence was revoked. Contact application support."
	case "device_limit_reached":
		return "The device limit is reached. Release an existing device or contact application support."
	case "device_mismatch", "device_identity_unavailable":
		return "This device could not be verified. Contact application support."
	case "concurrent_session_limit_reached":
		return "All floating seats are in use. Try again later or contact application support."
	case "session_required":
		return "Start a floating session before continuing."
	case "reset_cooldown":
		return "Device changes are temporarily limited. Wait before trying again."
	case "app_version_unsupported":
		return "This application version is no longer supported. Update the application to continue."
	case "application_maintenance":
		return "The application is under maintenance. Try again after maintenance ends."
	case "rate_limited":
		return "Too many requests. Wait before trying again."
	case "service_unavailable":
		return "Orbit is temporarily unavailable. Try again later."
	case "invalid_download_ticket":
		return "The download ticket is invalid or expired."
	default:
		return ""
	}
}

func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && e.Kind == t.Kind && (t.Code == "" || e.Code == t.Code)
}

var (
	ErrConfiguration   = &Error{Kind: Configuration}
	ErrCancelled       = &Error{Kind: Cancelled}
	ErrTransient       = &Error{Kind: Transient}
	ErrDenied          = &Error{Kind: Denied}
	ErrSessionRequired = &Error{Kind: Denied, Code: "session_required"}
	// ErrAppVersionUnsupported is a final policy denial for Options.AppVersion.
	// Update the application; cached or offline access is not used.
	ErrAppVersionUnsupported    = &Error{Kind: Denied, Code: "app_version_unsupported"}
	ErrNotActivated             = &Error{Kind: NotActivated, Code: "access_unavailable"}
	ErrFeatureUnavailable       = &Error{Kind: FeatureUnavailable, Code: "feature_unavailable"}
	ErrInvalidResponse          = &Error{Kind: InvalidResponse}
	ErrTransportSecurity        = &Error{Kind: TransportSecurity}
	ErrReauthenticationRequired = &Error{Kind: ReauthenticationRequired}
	ErrStaleResponse            = &Error{Kind: StaleResponse}
	ErrStorage                  = &Error{Kind: StorageFailure}
	ErrNativeSupportRequired    = &Error{Kind: StorageFailure, Code: "macos_cgo_required"}
	ErrClockUncertain           = &Error{Kind: ClockUncertain}
)

// errClosed matches ErrCancelled and reports use of a closed client.
var errClosed = &Error{Kind: Cancelled, Code: "closed"}

var ErrInstallationInUse = &Error{Kind: StorageFailure, Code: "installation_in_use"}
var ErrPendingActivation = &Error{Kind: StorageFailure, Code: "pending_activation"}
var ErrPendingActivationExpired = &Error{Kind: StorageFailure, Code: "pending_activation_expired"}
