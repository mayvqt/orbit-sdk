package orbit

import (
	"errors"
	"time"
)

// SupportSummary contains copyable diagnostics, never authentication or access proof.
type SupportSummary struct {
	ApplicationID string  `json:"application_id"`
	EnvironmentID string  `json:"environment_id"`
	Code          string  `json:"code"`
	RequestID     *string `json:"request_id"`
	// Timestamp is local Unix seconds, or nil when unavailable; not an access clock.
	Timestamp *int64 `json:"timestamp"`
}

// SupportSummary reads only configured public scope and the supplied error.
// It does not read account, access, device or storage state or contact Orbit.
func (c *Client) SupportSummary(err error) SupportSummary {
	summary := SupportSummary{ApplicationID: c.config.ApplicationID, EnvironmentID: c.config.EnvironmentID, Code: "unknown_error"}
	now := time.Now().Unix()
	if now >= 0 {
		summary.Timestamp = &now
	}
	var failure *Error
	if !errors.As(err, &failure) || failure == nil {
		return summary
	}
	switch failure.Kind {
	case Configuration, Cancelled, Transient, Denied, InvalidResponse, TransportSecurity,
		ReauthenticationRequired, StaleResponse, StorageFailure, ClockUncertain:
		summary.Code = string(failure.Kind)
	}
	if failure.Kind == Denied || failure.Kind == Transient {
		if errorCode(failure.Code) {
			summary.Code = failure.Code
		}
		if validRequestID(failure.RequestID) {
			requestID := failure.RequestID
			summary.RequestID = &requestID
		}
	}
	return summary
}

func validRequestID(value string) bool { return len(value) <= 64 && asciiToken(value) }
