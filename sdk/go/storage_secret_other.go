//go:build !linux

package orbit

// OpenSecretServiceStorage fails closed without the Linux Secret Service adapter.
func OpenSecretServiceStorage(directory string, config Config, device Device) (*SecretServiceStorage, error) {
	return nil, ErrStorage
}
