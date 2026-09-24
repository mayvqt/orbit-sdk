//go:build !linux && !windows

package orbit

func NativeFingerprint(applicationID, environmentID string) (string, error) {
	return "", &Error{Kind: Denied, Code: "device_identity_unavailable"}
}
