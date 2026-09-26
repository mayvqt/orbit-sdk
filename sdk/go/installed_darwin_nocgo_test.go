//go:build darwin && !cgo

package orbit

import (
	"errors"
	"testing"
)

func TestCGODisabledInstalledClientIsRejected(t *testing.T) {
	if _, _, _, err := openInstalledFiles("/tmp/orbit-cgo-disabled", nil); !errors.Is(err, ErrNativeSupportRequired) {
		t.Fatalf("installed storage did not explain the native prerequisite: %v", err)
	}
	if _, err := elapsedClock(); !errors.Is(err, ErrClockUncertain) {
		t.Fatalf("unsupported elapsed clock did not fail closed: %v", err)
	}
}
