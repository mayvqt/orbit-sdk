//go:build darwin && cgo

package orbit

/*
#cgo CFLAGS: -mmacosx-version-min=10.12
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include "macos_native.h"
*/
import "C"

import (
	"sync"
	"time"
)

var machTimebase struct {
	sync.Once
	numerator, denominator uint32
	err                    error
}

func elapsedClock() (time.Duration, error) {
	machTimebase.Do(func() {
		var numerator, denominator C.uint32_t
		if C.orbit_mach_timebase(&numerator, &denominator) != 0 || numerator == 0 || denominator == 0 {
			machTimebase.err = ErrClockUncertain
			return
		}
		machTimebase.numerator, machTimebase.denominator = uint32(numerator), uint32(denominator)
	})
	if machTimebase.err != nil {
		return 0, ErrClockUncertain
	}
	ticks := uint64(C.orbit_mach_continuous_time())
	return scaleMachTicks(ticks, machTimebase.numerator, machTimebase.denominator)
}
