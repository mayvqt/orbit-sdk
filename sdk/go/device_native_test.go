package orbit

import (
	"os"
	"testing"
)

func TestNativeFingerprintMatchesOSIdentity(t *testing.T) {
	if os.Getenv("ORBIT_NATIVE_FINGERPRINT_TEST") != "1" {
		t.Skip("native fingerprint acceptance requires explicit enablement")
	}
	expected := os.Getenv("ORBIT_NATIVE_FINGERPRINT_EXPECTED")
	if !lowerHex(expected, 64) {
		t.Fatal("native fingerprint acceptance requires a 64-character lowercase hexadecimal expected digest")
	}
	for attempt := 0; attempt < 2; attempt++ {
		actual, err := NativeFingerprint("native_test_app", "native_test_env")
		if err != nil {
			t.Fatal("native fingerprint acquisition failed")
		}
		if actual != expected {
			t.Fatal("native fingerprint did not match the independently calculated OS identity digest")
		}
	}
	for _, scope := range [][2]string{
		{"native_other_app", "native_test_env"},
		{"native_test_app", "native_other_env"},
	} {
		actual, err := NativeFingerprint(scope[0], scope[1])
		if err != nil || !lowerHex(actual, 64) {
			t.Fatal("changed scope did not produce a valid native fingerprint")
		}
		if actual == expected {
			t.Fatal("native fingerprint did not change with its scope")
		}
	}
}
