//go:build !windows

package orbit

import (
	"errors"
	"testing"
)

func TestWindowsStorageUnsupportedPlatform(t *testing.T) {
	config, device, _ := storageFixture()
	if storage, err := OpenWindowsStorage(t.TempDir(), config, device); storage != nil || !errors.Is(err, ErrStorage) {
		t.Fatal("unsupported protected storage did not fail closed")
	}
}
