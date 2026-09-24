package orbit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// Device identifies one installation; persist InstallationID separately from
// credentials. Fingerprint fields must either both be nil or both be supplied.
type Device struct {
	InstallationID      string
	Fingerprint         *string
	FingerprintProvider *string
}

func NewInstallation() (Device, error) {
	var entropy [24]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return Device{}, ErrConfiguration
	}
	return Device{InstallationID: base64.RawURLEncoding.EncodeToString(entropy[:])}, nil
}

// MachineFingerprint derives machine_v1 without exporting the raw OS ID.
func MachineFingerprint(applicationID, environmentID, osFamily, machineID string) (string, error) {
	if !opaque(applicationID) || !opaque(environmentID) || (osFamily != "linux" && osFamily != "windows") {
		return "", ErrConfiguration
	}
	normalized := strings.ToLower(strings.ReplaceAll(strings.Trim(machineID, " \t\n\r\v\f"), "-", ""))
	if !lowerHex(normalized, 32) || normalized == strings.Repeat("0", 32) || normalized == strings.Repeat("f", 32) {
		return "", &Error{Kind: Denied, Code: "device_identity_unavailable"}
	}
	digest := sha256.Sum256([]byte("orbit-machine-v1\n" + applicationID + "\n" + environmentID + "\n" + osFamily + "\n" + normalized))
	return hex.EncodeToString(digest[:]), nil
}
func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validProvider(value string) bool {
	if value == "machine_v1" {
		return true
	}
	if !strings.HasPrefix(value, "custom:") || len(value) <= 7 || len(value) > 55 {
		return false
	}
	for _, c := range value[7:] {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
