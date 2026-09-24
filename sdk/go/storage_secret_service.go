package orbit

import "fmt"

// SecretServiceStorage protects one explicit scope using the host's Linux
// Secret Service. It requires an operational keyring and /usr/bin/secret-tool.
// Share one object between contexts and Close it to release its lifetime lease.
// MemoryStorage remains the default; other platforms fail closed.
type SecretServiceStorage protectedStorage

func (SecretServiceStorage) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("[Orbit Secret Service storage]"))
}
func (SecretServiceStorage) MarshalJSON() ([]byte, error) { return nil, ErrStorage }
func (s *SecretServiceStorage) Load() (uint64, *StoredCredential, error) {
	return (*protectedStorage)(s).Load()
}
func (s *SecretServiceStorage) Version() (uint64, error) { return (*protectedStorage)(s).Version() }
func (s *SecretServiceStorage) Save(version uint64, credential StoredCredential) error {
	return (*protectedStorage)(s).Save(version, credential)
}
func (s *SecretServiceStorage) Invalidate() (uint64, error) {
	return (*protectedStorage)(s).Invalidate()
}

// Close releases ownership and discards the cached credential. Repeated Close
// calls are harmless; all other operations fail once the adapter is closed.
func (s *SecretServiceStorage) Close() error { return (*protectedStorage)(s).Close() }
