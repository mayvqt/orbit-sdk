package orbit

import (
	"fmt"
	"math"
	"sync"
)

// StoredCredential is sensitive bearer material. Storage adapters must protect
// it using an OS keyring or an explicitly selected equivalent protected store.
type StoredCredential struct {
	ApplicationID       string
	EnvironmentID       string
	ActivationID        string
	LicenceID           string
	InstallationID      string
	Credential          string
	CredentialExpiresAt int64 // Zero denotes an explicitly negotiated persistent credential.
	Fingerprint         *string
	FingerprintProvider *string
}

func (StoredCredential) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("[Orbit credential redacted]"))
}
func (StoredCredential) MarshalJSON() ([]byte, error) { return nil, ErrStorage }

// Storage coordinates all readers and writers of one access context. Save must
// atomically compare its version with Invalidate. Adapters must not persist
// credentials in plaintext. Errors are redacted at the client boundary.
type Storage interface {
	Version() (uint64, error)
	Load() (uint64, *StoredCredential, error)
	Save(version uint64, credential StoredCredential) error
	Invalidate() (uint64, error)
}

// MemoryStorage is the default and retains no data after process exit.
// Its zero value is ready to use.
type MemoryStorage struct {
	mu         sync.Mutex
	version    uint64
	credential *StoredCredential
}

func (s *MemoryStorage) Version() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version, nil
}
func (s *MemoryStorage) Load() (uint64, *StoredCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version, cloneCredential(s.credential), nil
}
func (s *MemoryStorage) Save(version uint64, credential StoredCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if version != s.version {
		return ErrStaleResponse
	}
	s.credential = cloneCredential(&credential)
	return nil
}
func (s *MemoryStorage) Invalidate() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.credential = nil
	if s.version == math.MaxUint64 {
		return 0, ErrStorage
	}
	s.version++
	return s.version, nil
}
func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}
func equalString(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func cloneCredential(value *StoredCredential) *StoredCredential {
	if value == nil {
		return nil
	}
	copied := *value
	copied.Fingerprint = cloneString(value.Fingerprint)
	copied.FingerprintProvider = cloneString(value.FingerprintProvider)
	return &copied
}
