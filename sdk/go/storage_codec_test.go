package orbit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func storageFixture() (Config, Device, StoredCredential) {
	config := Config{Issuer: "issuer", ApplicationID: "app", EnvironmentID: "test"}
	device := Device{InstallationID: "installation_1234"}
	credential := StoredCredential{ApplicationID: config.ApplicationID, EnvironmentID: config.EnvironmentID,
		InstallationID: device.InstallationID, ActivationID: "activation", LicenceID: "licence",
		Credential: strings.Repeat("c", 43), CredentialExpiresAt: 1800003600}
	return config, device, credential
}

func fixtureStorageScope(t *testing.T) storageScope {
	t.Helper()
	config, device, _ := storageFixture()
	scope, err := newStorageScope(config, device)
	if err != nil {
		t.Fatal("fixture scope failed")
	}
	return scope
}

func TestStorageEntropyFraming(t *testing.T) {
	scope := fixtureStorageScope(t)
	expected := sha256.Sum256([]byte("orbit.sdk.storage.v1\x00" +
		"\x00\x00\x00\x06issuer\x00\x00\x00\x03app\x00\x00\x00\x04test" +
		"\x00\x00\x00\x11installation_1234"))
	if scope.entropy != expected {
		t.Fatal("storage entropy does not match the fixed domain and u32 framing")
	}
	config, device, _ := storageFixture()
	for _, change := range []func(*Config, *Device){
		func(c *Config, _ *Device) { c.Issuer += "x" },
		func(c *Config, _ *Device) { c.ApplicationID += "x" },
		func(c *Config, _ *Device) { c.EnvironmentID += "x" },
		func(_ *Config, d *Device) { d.InstallationID += "x" },
	} {
		otherConfig, otherDevice := config, device
		change(&otherConfig, &otherDevice)
		other, err := newStorageScope(otherConfig, otherDevice)
		if err != nil || other.entropy == expected {
			t.Fatal("a changed scope reused storage entropy")
		}
	}
	config.Issuer, config.ApplicationID = "a", "bc"
	one, _ := newStorageScope(config, device)
	config.Issuer, config.ApplicationID = "ab", "c"
	two, _ := newStorageScope(config, device)
	if one.entropy == two.entropy {
		t.Fatal("scope framing permits component-boundary ambiguity")
	}
}

func TestStorageCodecRoundTripAndTombstones(t *testing.T) {
	config, device, credential := storageFixture()
	for _, bound := range []bool{false, true} {
		if bound {
			fingerprint, provider := strings.Repeat("a", 64), "machine_v1"
			device.Fingerprint, device.FingerprintProvider = &fingerprint, &provider
			credential.Fingerprint, credential.FingerprintProvider = &fingerprint, &provider
		}
		scope, err := newStorageScope(config, device)
		if err != nil {
			t.Fatal("fixture binding failed")
		}
		for _, value := range []*StoredCredential{nil, &credential} {
			for _, generation := range []uint64{0, 1, math.MaxInt64} {
				data, err := encodeStorageRecord(scope, generation, value)
				if err != nil {
					t.Fatal("private codec could not encode a valid fixture")
				}
				actualGeneration, actual, err := decodeStorageRecord(scope, data)
				if err != nil || generation != actualGeneration || !reflect.DeepEqual(value, actual) {
					t.Fatal("private codec round trip changed state")
				}
				clear(data)
			}
		}
	}
}

func TestStorageCodecRejectsCorruptAndUnknownRecords(t *testing.T) {
	scope := fixtureStorageScope(t)
	_, _, credential := storageFixture()
	valid, _ := encodeStorageRecord(scope, 7, &credential)
	for length := 0; length < len(valid); length++ {
		if _, value, err := decodeStorageRecord(scope, valid[:length]); value != nil || !errors.Is(err, ErrStorage) {
			t.Fatal("truncated storage record was accepted")
		}
	}
	cases := [][]byte{append(bytes.Clone(valid), 0), make([]byte, storagePlaintextLimit+1)}
	for _, offset := range []int{0, 3, 16} {
		corrupt := bytes.Clone(valid)
		corrupt[offset] = 0xff
		cases = append(cases, corrupt)
	}
	overflow := bytes.Clone(valid)
	binary.BigEndian.PutUint64(overflow[4:12], math.MaxUint64)
	cases = append(cases, overflow)
	for _, expiry := range []uint64{0, math.MaxUint64} {
		corrupt := bytes.Clone(valid)
		binary.BigEndian.PutUint64(corrupt[len(corrupt)-8:], expiry)
		cases = append(cases, corrupt)
	}
	hugeField := bytes.Clone(valid)
	binary.BigEndian.PutUint32(hugeField[12:16], math.MaxUint32)
	cases = append(cases, hugeField)
	for _, data := range cases {
		if _, value, err := decodeStorageRecord(scope, data); value != nil || !errors.Is(err, ErrStorage) {
			t.Fatal("invalid storage record was accepted")
		}
	}
	if _, err := encodeStorageRecord(scope, math.MaxUint64, nil); !errors.Is(err, ErrStorage) {
		t.Fatal("unbounded generation was encoded")
	}
	config := scope.config
	config.Issuer += "other"
	other, _ := newStorageScope(config, scope.device)
	if _, _, err := decodeStorageRecord(other, valid); !errors.Is(err, ErrStorage) {
		t.Fatal("wrong scope was accepted by the private codec")
	}
	credential.Credential = "invalid"
	if _, err := encodeStorageRecord(scope, 0, &credential); !errors.Is(err, ErrStorage) {
		t.Fatal("malformed credential was encoded")
	}
}

// The portable state fixture is memory-only; native tests use actual DPAPI/files.
type codecStorageFiles struct {
	data []byte
	fail bool
}

func (f *codecStorageFiles) read(scope storageScope) (uint64, *StoredCredential, error) {
	return decodeStorageRecord(scope, f.data)
}
func (f *codecStorageFiles) write(scope storageScope, version uint64, value *StoredCredential) error {
	if f.fail {
		return ErrStorage
	}
	data, err := encodeStorageRecord(scope, version, value)
	if err == nil {
		clear(f.data)
		f.data = data
	}
	return err
}
func (f *codecStorageFiles) close() error { clear(f.data); f.data = nil; return nil }

func TestProtectedStorageGenerationPoisonAndClose(t *testing.T) {
	scope := fixtureStorageScope(t)
	_, _, credential := storageFixture()
	files := &codecStorageFiles{}
	_ = files.write(scope, 0, nil)
	storage := &WindowsStorage{state: &protectedStorageState{scope: scope, files: files}}
	if err := storage.Save(0, credential); err != nil {
		t.Fatal("initial save failed")
	}
	version, err := storage.Invalidate()
	if err != nil || version != 1 {
		t.Fatal("invalidation did not advance generation")
	}
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Go(func() {
			if !errors.Is(storage.Save(0, credential), ErrStaleResponse) {
				t.Error("late writer restored invalidated state")
			}
		})
	}
	group.Wait()
	if version, value, err := storage.Load(); err != nil || version != 1 || value != nil {
		t.Fatal("tombstone changed after stale writes")
	}
	files.fail = true
	if !errors.Is(storage.Save(1, credential), ErrStorage) {
		t.Fatal("failed write did not fail closed")
	}
	files.fail = false
	if _, err := storage.Version(); !errors.Is(err, ErrStorage) {
		t.Fatal("failed adapter did not remain poisoned")
	}
	if storage.Close() != nil || storage.Close() != nil || storage.state.scope.config.Issuer != "" {
		t.Fatal("close did not clear scope and release ownership")
	}
	if _, _, err := storage.Load(); !errors.Is(err, ErrStorage) || !errors.Is(storage.Save(1, credential), ErrStorage) {
		t.Fatal("closed storage remained usable")
	}
	if _, err := storage.Invalidate(); !errors.Is(err, ErrStorage) {
		t.Fatal("closed storage permitted invalidation")
	}
}

func TestStorageRedactionGuardsRemainClosed(t *testing.T) {
	_, _, credential := storageFixture()
	for _, value := range []any{credential, &credential, WindowsStorage{}, &WindowsStorage{}, SecretServiceStorage{}, &SecretServiceStorage{}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(format, value), credential.Credential) {
				t.Fatal("ordinary formatting exposed a credential")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrStorage) {
			t.Fatal("ordinary serialization did not reject protected storage material")
		}
	}
}
