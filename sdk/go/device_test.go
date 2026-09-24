package orbit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestMachineFingerprintGoldenFraming(t *testing.T) {
	// Literal golden preimages fix every separator, scope and OS byte and the
	// absence of a final newline independently of production framing code.
	vectors := []struct {
		application, environment, osFamily, machineID, preimage string
	}{
		{"app", "test", "linux", "00112233445566778899aabbccddeeff", "orbit-machine-v1\napp\ntest\nlinux\n00112233445566778899aabbccddeeff"},
		{"app", "test", "linux", " \t\r\n00112233-4455-6677-8899-AABBCCDDEEFF\v\f ", "orbit-machine-v1\napp\ntest\nlinux\n00112233445566778899aabbccddeeff"},
		{"app", "test", "windows", "00112233-4455-6677-8899-AABBCCDDEEFF", "orbit-machine-v1\napp\ntest\nwindows\n00112233445566778899aabbccddeeff"},
		{"other_app", "live", "linux", "0123456789ABCDEF0123456789ABCDEF", "orbit-machine-v1\nother_app\nlive\nlinux\n0123456789abcdef0123456789abcdef"},
	}
	for _, vector := range vectors {
		digest := sha256.Sum256([]byte(vector.preimage))
		expected := hex.EncodeToString(digest[:])
		actual, err := MachineFingerprint(vector.application, vector.environment, vector.osFamily, vector.machineID)
		if err != nil || actual != expected {
			t.Fatalf("%s/%s/%s: got %q, %v; want %q", vector.application, vector.environment, vector.osFamily, actual, err, expected)
		}
	}
}

func TestMachineFingerprintRejectsUnavailableIdentity(t *testing.T) {
	for _, machineID := range []string{"", strings.Repeat("0", 32), strings.Repeat("F", 32), "00112233445566778899aabbccddeef", "00112233445566778899aabbccddeeff00", "00112233445566778899aabbccddeefg", "00112233 445566778899aabbccddeeff", "\u00a000112233445566778899aabbccddeeff"} {
		if _, err := MachineFingerprint("app", "test", "linux", machineID); err == nil {
			t.Fatalf("accepted invalid synthetic machine ID: %q", machineID)
		}
	}
	for _, scope := range [][3]string{{"app\nother", "test", "linux"}, {"app", "test/live", "linux"}, {"app", "test", "macos"}} {
		if _, err := MachineFingerprint(scope[0], scope[1], scope[2], "00112233445566778899aabbccddeeff"); err == nil {
			t.Fatalf("accepted invalid fingerprint scope: %q", scope)
		}
	}
}

func TestCustomProviderConfigurationMatchesService(t *testing.T) {
	fingerprint := strings.Repeat("a", 64)
	transport, err := NewTransport("https://orbit.example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"machine_v1", "custom:acme.v1", "custom:a-b_c.09", "custom:" + strings.Repeat("a", 48)} {
		client, err := NewClient(Config{ApplicationID: "app", EnvironmentID: "test", Issuer: "https://orbit.example.test"}, Device{InstallationID: "installation_1234", Fingerprint: &fingerprint, FingerprintProvider: &provider}, transport)
		if err != nil || client == nil {
			t.Fatalf("valid provider rejected: %q", provider)
		}
	}
	for _, provider := range []string{"", "custom:", "custom:UPPER", "custom:a/b", "custom:a b", "custom:é", "custom:" + strings.Repeat("a", 49)} {
		if _, err := NewClient(Config{ApplicationID: "app", EnvironmentID: "test", Issuer: "https://orbit.example.test"}, Device{InstallationID: "installation_1234", Fingerprint: &fingerprint, FingerprintProvider: &provider}, transport); err == nil {
			t.Fatalf("invalid provider accepted: %q", provider)
		}
	}
}
