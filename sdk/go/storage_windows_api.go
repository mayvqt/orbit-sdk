package orbit

import "fmt"

// WindowsStorage protects one explicit scope with current-user Windows DPAPI.
// Share one object between contexts; Close ends its exclusive lifetime lease.
// MemoryStorage remains the default. No customer session or grant is persisted.
type WindowsStorage protectedStorage

func (WindowsStorage) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte("[Orbit Windows storage]")) }
func (WindowsStorage) MarshalJSON() ([]byte, error) { return nil, ErrStorage }
func (s *WindowsStorage) Load() (uint64, *StoredCredential, error) {
	return (*protectedStorage)(s).Load()
}
func (s *WindowsStorage) Version() (uint64, error) { return (*protectedStorage)(s).Version() }
func (s *WindowsStorage) Save(version uint64, credential StoredCredential) error {
	return (*protectedStorage)(s).Save(version, credential)
}
func (s *WindowsStorage) Invalidate() (uint64, error) { return (*protectedStorage)(s).Invalidate() }

// Close releases the lease and clears scope; subsequent operations fail closed.
func (s *WindowsStorage) Close() error { return (*protectedStorage)(s).Close() }
