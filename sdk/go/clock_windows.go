//go:build windows

package orbit

import (
	"math"
	"syscall"
	"time"
	"unsafe"
)

// Windows resolves this API-set contract through its system API-set map.
// Biased interrupt time includes both suspend and hibernate.
var interruptTime = syscall.NewLazyDLL("api-ms-win-core-realtime-l1-1-1.dll").NewProc("QueryInterruptTimePrecise")

func elapsedClock() (time.Duration, error) {
	if err := interruptTime.Find(); err != nil {
		return 0, ErrClockUncertain
	}
	var ticks uint64
	// The Windows function returns void and initializes this synchronous out
	// parameter; GetLastError is not a success indicator for this API.
	interruptTime.Call(uintptr(unsafe.Pointer(&ticks)))
	if ticks > math.MaxInt64/100 {
		return 0, ErrClockUncertain
	}
	return time.Duration(ticks * 100), nil
}
