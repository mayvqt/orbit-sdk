package orbit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"unicode/utf8"
)

const storagePlaintextLimit = 32768
const storageCiphertextLimit = 65536

type storageScope struct {
	config  Config
	device  Device
	entropy [32]byte
}

func newStorageScope(config Config, device Device) (storageScope, error) {
	if !opaque(config.ApplicationID) || !opaque(config.EnvironmentID) || config.Issuer == "" || len(config.Issuer) > storagePlaintextLimit || !utf8.ValidString(config.Issuer) || !opaque(device.InstallationID) || len(device.InstallationID) < 16 || (device.Fingerprint == nil) != (device.FingerprintProvider == nil) || device.Fingerprint != nil && !lowerHex(*device.Fingerprint, 64) || device.FingerprintProvider != nil && !validProvider(*device.FingerprintProvider) {
		return storageScope{}, ErrConfiguration
	}
	device.Fingerprint = cloneString(device.Fingerprint)
	device.FingerprintProvider = cloneString(device.FingerprintProvider)
	scope := storageScope{config: config, device: device}
	hash := sha256.New()
	_, _ = hash.Write([]byte("orbit.sdk.storage.v1\x00"))
	for _, value := range []string{config.Issuer, config.ApplicationID, config.EnvironmentID, device.InstallationID} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	copy(scope.entropy[:], hash.Sum(nil))
	return scope, nil
}

func (scope storageScope) accepts(credential *StoredCredential) bool {
	return credential == nil || credential.ApplicationID == scope.config.ApplicationID &&
		credential.EnvironmentID == scope.config.EnvironmentID && credential.InstallationID == scope.device.InstallationID &&
		equalString(credential.Fingerprint, scope.device.Fingerprint) && equalString(credential.FingerprintProvider, scope.device.FingerprintProvider) &&
		opaque(credential.ActivationID) && opaque(credential.LicenceID) && bearer(credential.Credential) && credential.CredentialExpiresAt > 0
}

// This private, fixed binary record never uses StoredCredential's public JSON
// surface. OGS identifies the Go SDK; version 1 accepts no extra fields/bytes.
func encodeStorageRecord(scope storageScope, generation uint64, credential *StoredCredential) ([]byte, error) {
	if generation > math.MaxInt64 || !scope.accepts(credential) {
		return nil, ErrStorage
	}
	data := binary.BigEndian.AppendUint64([]byte{'O', 'G', 'S', 1}, generation)
	appendString := func(value string) {
		data = binary.BigEndian.AppendUint32(data, uint32(len(value)))
		data = append(data, value...)
	}
	for _, value := range []string{scope.config.Issuer, scope.config.ApplicationID, scope.config.EnvironmentID, scope.device.InstallationID} {
		appendString(value)
	}
	for _, value := range []*string{scope.device.Fingerprint, scope.device.FingerprintProvider} {
		if value == nil {
			data = append(data, 0)
		} else {
			data = append(data, 1)
			appendString(*value)
		}
	}
	if credential == nil {
		data = append(data, 0)
	} else {
		data = append(data, 1)
		for _, value := range []string{credential.ActivationID, credential.LicenceID, credential.Credential} {
			appendString(value)
		}
		data = binary.BigEndian.AppendUint64(data, uint64(credential.CredentialExpiresAt))
	}
	if len(data) > storagePlaintextLimit {
		clear(data)
		return nil, ErrStorage
	}
	return data, nil
}

type storageDecoder struct {
	data []byte
	bad  bool
}

func (d *storageDecoder) take(size int) []byte {
	if size < 0 || size > len(d.data) {
		d.bad = true
		return nil
	}
	value := d.data[:size]
	d.data = d.data[size:]
	return value
}

func (d *storageDecoder) number() uint64 {
	value := d.take(8)
	if len(value) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(value)
}

func (d *storageDecoder) text(limit uint32) string {
	prefix := d.take(4)
	if len(prefix) != 4 {
		return ""
	}
	size := binary.BigEndian.Uint32(prefix)
	if size > limit || uint64(size) > uint64(len(d.data)) {
		d.bad = true
		return ""
	}
	value := d.take(int(size))
	if !utf8.Valid(value) {
		d.bad = true
	}
	return string(value)
}

func (d *storageDecoder) present() bool {
	flag := d.take(1)
	if len(flag) != 1 || flag[0] > 1 {
		d.bad = true
		return false
	}
	return flag[0] == 1
}

func (d *storageDecoder) optional(limit uint32) *string {
	if !d.present() {
		return nil
	}
	value := d.text(limit)
	return &value
}

func decodeStorageRecord(scope storageScope, data []byte) (uint64, *StoredCredential, error) {
	if len(data) > storagePlaintextLimit {
		return 0, nil, ErrStorage
	}
	d := storageDecoder{data: data}
	if !bytes.Equal(d.take(4), []byte{'O', 'G', 'S', 1}) {
		return 0, nil, ErrStorage
	}
	generation := d.number()
	issuer, application, environment, installation := d.text(storagePlaintextLimit), d.text(128), d.text(128), d.text(128)
	fingerprint, provider := d.optional(64), d.optional(55)
	if d.bad || generation > math.MaxInt64 || issuer != scope.config.Issuer || application != scope.config.ApplicationID || environment != scope.config.EnvironmentID || installation != scope.device.InstallationID || !equalString(fingerprint, scope.device.Fingerprint) || !equalString(provider, scope.device.FingerprintProvider) {
		return 0, nil, ErrStorage
	}
	var credential *StoredCredential
	if d.present() {
		credential = &StoredCredential{ApplicationID: application, EnvironmentID: environment, InstallationID: installation,
			Fingerprint: fingerprint, FingerprintProvider: provider,
			ActivationID: d.text(128), LicenceID: d.text(128), Credential: d.text(43)}
		expiry := d.number()
		if expiry > math.MaxInt64 {
			return 0, nil, ErrStorage
		}
		credential.CredentialExpiresAt = int64(expiry)
	}
	if d.bad || len(d.data) != 0 || !scope.accepts(credential) {
		return 0, nil, ErrStorage
	}
	return generation, credential, nil
}
