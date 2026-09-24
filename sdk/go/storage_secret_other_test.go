//go:build !linux

package orbit

import (
	"errors"
	"testing"
)

func TestSecretServiceStorageUnsupportedPlatform(t *testing.T) {
	config, device, _ := storageFixture()
	if storage, err := OpenSecretServiceStorage(t.TempDir(), config, device); storage != nil || !errors.Is(err, ErrStorage) {
		t.Fatal("unsupported Secret Service storage did not fail closed")
	}
}
