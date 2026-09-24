//go:build linux

package orbit

import (
	"io"
	"os"
)

// NativeFingerprint reads Linux's installation identity with a strict byte cap.
func NativeFingerprint(applicationID, environmentID string) (string, error) {
	file, err := os.Open("/etc/machine-id")
	if err != nil {
		return "", &Error{Kind: Denied, Code: "device_identity_unavailable"}
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil || len(value) > 256 {
		return "", &Error{Kind: Denied, Code: "device_identity_unavailable"}
	}
	return MachineFingerprint(applicationID, environmentID, "linux", string(value))
}
