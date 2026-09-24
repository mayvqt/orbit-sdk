package orbit

import (
	"errors"
	"math"
	"sync"
)

type protectedStorageFiles interface {
	read(storageScope) (uint64, *StoredCredential, error)
	write(storageScope, uint64, *StoredCredential) error
	close() error
}

type protectedStorageState struct {
	mu       sync.Mutex
	files    protectedStorageFiles
	scope    storageScope
	closed   bool
	poisoned bool
}

const storageLockName = "orbit-storage.lock"

var errStorageMissing = errors.New("missing protected storage record")

type protectedStorage struct {
	state *protectedStorageState
}

func (s *protectedStorage) loadLocked() (uint64, *StoredCredential, error) {
	if s.state.closed || s.state.poisoned {
		return 0, nil, ErrStorage
	}
	version, credential, err := s.state.files.read(s.state.scope)
	if err != nil {
		s.state.poisoned = true
		return 0, nil, ErrStorage
	}
	return version, credential, nil
}

func (s *protectedStorage) Load() (uint64, *StoredCredential, error) {
	if s == nil || s.state == nil {
		return 0, nil, ErrStorage
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	return s.loadLocked()
}

func (s *protectedStorage) Version() (uint64, error) {
	version, _, err := s.Load()
	return version, err
}

func (s *protectedStorage) Save(expected uint64, credential StoredCredential) error {
	if s == nil || s.state == nil {
		return ErrStorage
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	version, _, err := s.loadLocked()
	if err != nil {
		return err
	}
	if expected != version {
		return ErrStaleResponse
	}
	if s.state.files.write(s.state.scope, version, &credential) != nil {
		s.state.poisoned = true
		return ErrStorage
	}
	return nil
}

func (s *protectedStorage) Invalidate() (uint64, error) {
	if s == nil || s.state == nil {
		return 0, ErrStorage
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	version, _, err := s.loadLocked()
	if err != nil {
		return 0, err
	}
	if version == math.MaxInt64 || s.state.files.write(s.state.scope, version+1, nil) != nil {
		s.state.poisoned = true
		return 0, ErrStorage
	}
	return version + 1, nil
}

// Close clears the adapter's scope and releases its OS lease. All storage
// operations then fail; repeated Close calls are harmless. Returned credentials
// belong to their callers; the provider discards any private cached record.
func (s *protectedStorage) Close() error {
	if s == nil || s.state == nil {
		return ErrStorage
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if s.state.closed {
		return nil
	}
	s.state.closed = true
	s.state.scope = storageScope{}
	err := s.state.files.close()
	s.state.files = nil
	if err != nil {
		return ErrStorage
	}
	return nil
}
