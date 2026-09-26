package orbit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
		{"app", "test", "macos", "00112233-4455-6677-8899-AABBCCDDEEFF", "orbit-machine-v1\napp\ntest\nmacos\n00112233445566778899aabbccddeeff"},
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

func TestMacOSPlatformUUIDFingerprintFixture(t *testing.T) {
	const uuid = "00112233-4455-6677-8899-AABBCCDDEEFF"
	const expected = "ccd81e8a12bd6695ca8e0d71b409c58696e780780e2c9e1c14ea1aa7fe8e069a"
	actual, err := MachineFingerprint("app", "test", "macos", uuid)
	if err != nil || actual != expected {
		t.Fatalf("macOS UUID framing returned %q, %v", actual, err)
	}
}

func TestMachineFingerprintRejectsUnavailableIdentity(t *testing.T) {
	for _, machineID := range []string{"", strings.Repeat("0", 32), strings.Repeat("F", 32), "00112233445566778899aabbccddeef", "00112233445566778899aabbccddeeff00", "00112233445566778899aabbccddeefg", "00112233 445566778899aabbccddeeff", "\u00a000112233445566778899aabbccddeeff"} {
		if _, err := MachineFingerprint("app", "test", "linux", machineID); err == nil {
			t.Fatalf("accepted invalid synthetic machine ID: %q", machineID)
		}
	}
	for _, scope := range [][3]string{{"app\nother", "test", "linux"}, {"app", "test/live", "linux"}, {"app", "test", "other"}} {
		if _, err := MachineFingerprint(scope[0], scope[1], scope[2], "00112233445566778899aabbccddeeff"); err == nil {
			t.Fatalf("accepted invalid fingerprint scope: %q", scope)
		}
	}
}

func TestNormalizeMacOSPlatformUUIDRequiresCompleteBoundedASCII(t *testing.T) {
	raw := " \t00112233-4455-6677-8899-AABBCCDDEEFF\r\n"
	got, ok := normalizeMacOSPlatformUUID(raw, len(raw))
	if !ok || got != "00112233-4455-6677-8899-AABBCCDDEEFF" {
		t.Fatalf("ASCII whitespace was not normalized: %q %t", got, ok)
	}
	for _, value := range []string{
		"00112233-4455-6677-8899-AABBCCDDEEFF\x00ignored",
		"00112233-4455-6677-8899-AABBCCDDEEFé",
		strings.Repeat("a", 257),
	} {
		if _, ok := normalizeMacOSPlatformUUID(value, len(value)); ok {
			t.Fatalf("accepted incomplete, non-ASCII, or unbounded property %q", value)
		}
	}
	if _, ok := normalizeMacOSPlatformUUID("short", len("short")-1); ok {
		t.Fatal("accepted a converted C-string prefix")
	}
}

func TestCustomProviderConfigurationMatchesService(t *testing.T) {
	fingerprint := strings.Repeat("a", 64)
	transport, err := NewTransport("https://orbit.example.test")
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"machine_v1", "custom:acme.v1", "custom:a-b_c.09", "custom:" + strings.Repeat("a", 48)} {
		client, err := NewClient(testAppKey(), Device{InstallationID: "installation_1234", Fingerprint: &fingerprint, FingerprintProvider: &provider}, transport)
		if err != nil || client == nil {
			t.Fatalf("valid provider rejected: %q", provider)
		}
	}
	for _, provider := range []string{"", "custom:", "custom:UPPER", "custom:a/b", "custom:a b", "custom:é", "custom:" + strings.Repeat("a", 49)} {
		if _, err := NewClient(testAppKey(), Device{InstallationID: "installation_1234", Fingerprint: &fingerprint, FingerprintProvider: &provider}, transport); err == nil {
			t.Fatalf("invalid provider accepted: %q", provider)
		}
	}
}

func TestInstalledMachineBindingOptions(t *testing.T) {
	key := testAppKey()
	fingerprint, provider := strings.Repeat("a", 64), "custom:test-device"
	autoFingerprint, autoErr := NativeFingerprint(key.applicationID, key.environmentID)
	auto, autoProvider, err := resolveBinding(key, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if autoErr == nil {
		if auto == nil || *auto != autoFingerprint || autoProvider == nil || *autoProvider != "machine_v1" {
			t.Fatal("default options did not select the native machine identity")
		}
	} else {
		var failure *Error
		if !errors.As(autoErr, &failure) || failure.Code != "device_identity_unavailable" || auto != nil || autoProvider != nil {
			t.Fatalf("unavailable native identity did not fail open without a fingerprint: %v", autoErr)
		}
	}
	disabled, disabledProvider, err := resolveBinding(key, Options{BindingMode: BindingDisabled})
	if err != nil || disabled != nil || disabledProvider != nil {
		t.Fatal("disabled machine binding supplied a fingerprint")
	}
	custom, customProvider, err := resolveBinding(key, Options{BindingMode: BindingCustom, Fingerprint: fingerprint, FingerprintProvider: provider})
	if err != nil || custom == nil || *custom != fingerprint || customProvider == nil || *customProvider != provider {
		t.Fatalf("custom machine binding was not retained: %v", err)
	}
	if _, _, err := resolveBinding(key, Options{BindingMode: BindingCustom, Fingerprint: fingerprint, FingerprintProvider: "machine_v1"}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("custom mode accepted the built-in provider")
	}
}
