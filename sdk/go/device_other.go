//go:build !linux && !windows && !darwin

package orbit

func NativeFingerprint(applicationID, environmentID string) (string, error) {
	return "", &Error{Kind: Denied, Code: "device_identity_unavailable"}
}
