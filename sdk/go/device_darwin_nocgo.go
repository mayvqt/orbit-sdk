//go:build darwin && !cgo

package orbit

func NativeFingerprint(string, string) (string, error) {
	return "", &Error{Kind: Denied, Code: "device_identity_unavailable"}
}
