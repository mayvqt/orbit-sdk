//go:build windows

package orbit

import (
	"bytes"
	"errors"
	"testing"
	"unsafe"
)

func TestDPAPICurrentUserRoundTrip(t *testing.T) {
	entropy := []byte("orbit-synthetic-dpapi-test-scope")
	for name, plaintext := range map[string][]byte{
		"empty":   {},
		"binary":  {0, 1, 2, 0xff, 0, 0x80},
		"maximum": bytes.Repeat([]byte("synthetic"), maxUserPlaintext/9+1)[:maxUserPlaintext],
	} {
		t.Run(name, func(t *testing.T) {
			original := bytes.Clone(plaintext)
			ciphertext, err := protectUserData(plaintext, entropy)
			if err != nil {
				t.Fatalf("current-user DPAPI protection failed: %v", err)
			}
			if len(ciphertext) == 0 || len(ciphertext) > maxUserCiphertext || bytes.Equal(ciphertext, plaintext) {
				t.Fatal("DPAPI did not return a bounded protected value")
			}
			if !bytes.Equal(plaintext, original) {
				t.Fatal("protection changed the caller's plaintext")
			}
			protected := bytes.Clone(ciphertext)
			recovered, err := unprotectUserData(ciphertext, entropy)
			if err != nil || !bytes.Equal(recovered, original) {
				t.Fatalf("current-user DPAPI round-trip failed: %v", err)
			}
			if !bytes.Equal(ciphertext, protected) {
				t.Fatal("unprotection changed the caller's ciphertext")
			}
		})
	}
}

func TestDPAPIRejectsWrongEntropyAndTampering(t *testing.T) {
	entropy := []byte("orbit-synthetic-dpapi-test-scope")
	ciphertext, err := protectUserData([]byte("synthetic protected credential"), entropy)
	if err != nil {
		t.Fatalf("current-user DPAPI prerequisite failed: %v", err)
	}
	tampered := bytes.Clone(ciphertext)
	tampered[len(tampered)-1] ^= 0xff
	for _, fixture := range []struct {
		name                string
		ciphertext, entropy []byte
	}{
		{"wrong_entropy", ciphertext, []byte("another-synthetic-scope")},
		{"tampered", tampered, entropy},
		{"truncated", ciphertext[:len(ciphertext)/2], entropy},
		{"invalid", []byte("not a DPAPI blob"), entropy},
		{"empty", nil, entropy},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			result, err := unprotectUserData(fixture.ciphertext, fixture.entropy)
			if result != nil || !errors.Is(err, ErrStorage) {
				t.Fatalf("invalid protected data did not fail closed: %v", err)
			}
		})
	}
}

func TestDPAPIBoundsAndBlobLayout(t *testing.T) {
	if unsafe.Offsetof(userDataBlob{}.data) != unsafe.Sizeof(uintptr(0)) || unsafe.Sizeof(userDataBlob{}) != 2*unsafe.Sizeof(uintptr(0)) {
		t.Fatal("DATA_BLOB layout does not match the Windows pointer width")
	}
	for _, fixture := range []struct {
		name string
		call func() ([]byte, error)
	}{
		{"plaintext", func() ([]byte, error) { return protectUserData(make([]byte, maxUserPlaintext+1), []byte("scope")) }},
		{"ciphertext", func() ([]byte, error) { return unprotectUserData(make([]byte, maxUserCiphertext+1), []byte("scope")) }},
		{"protect_empty_entropy", func() ([]byte, error) { return protectUserData([]byte("synthetic"), nil) }},
		{"unprotect_empty_entropy", func() ([]byte, error) { return unprotectUserData([]byte("synthetic"), nil) }},
		{"protect_large_entropy", func() ([]byte, error) { return protectUserData([]byte("synthetic"), make([]byte, maxUserEntropy+1)) }},
		{"unprotect_large_entropy", func() ([]byte, error) { return unprotectUserData([]byte("synthetic"), make([]byte, maxUserEntropy+1)) }},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			result, err := fixture.call()
			if result != nil || !errors.Is(err, ErrStorage) {
				t.Fatalf("invalid input bounds did not fail closed: %v", err)
			}
		})
	}
	// Exercise the foreign-memory erasure loop on a synthetic buffer without
	// exposing the buffer in a failure message.
	data := bytes.Repeat([]byte{0xa5}, 64)
	zeroNativeUserData(&data[0], uint32(len(data)))
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("native data erasure left nonzero bytes")
	}
}

func TestDPAPIBoundsDecryptedNativeOutput(t *testing.T) {
	entropy := bytes.Repeat([]byte{0x5a}, maxUserEntropy)
	// A different current-user application could produce a valid DPAPI blob
	// whose plaintext exceeds this SDK's cap. Build that fixture through the
	// native call, bypassing only protectUserData's public input-size guard.
	ciphertext, err := transformUserData(userProtectProc, make([]byte, maxUserPlaintext+1), entropy, maxUserCiphertext)
	if err != nil {
		t.Fatalf("native oversized-output fixture failed: %v", err)
	}
	result, err := unprotectUserData(ciphertext, entropy)
	if result != nil || !errors.Is(err, ErrStorage) {
		t.Fatalf("oversized decrypted native data did not fail closed: %v", err)
	}
	// The exact entropy cap remains usable for ordinary protected data.
	ciphertext, err = protectUserData([]byte("synthetic"), entropy)
	if err != nil {
		t.Fatalf("maximum entropy protection failed: %v", err)
	}
	result, err = unprotectUserData(ciphertext, entropy)
	if err != nil || !bytes.Equal(result, []byte("synthetic")) {
		t.Fatalf("maximum entropy round-trip failed: %v", err)
	}
}
