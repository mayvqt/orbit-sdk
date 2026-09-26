//go:build linux

package orbit

import (
	"math"
	"syscall"
	"time"
	"unsafe"
)

// CLOCK_BOOTTIME includes suspend; time.Now's monotonic clock does not promise
// this. The native call is isolated here and never persists across a reboot.
func elapsedClock() (time.Duration, error) {
	var value syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 7, uintptr(unsafe.Pointer(&value)), 0)
	if errno != 0 || value.Sec < 0 || value.Nsec < 0 || value.Nsec >= 1e9 || int64(value.Sec) > math.MaxInt64/int64(time.Second)-1 {
		return 0, ErrClockUncertain
	}
	return time.Duration(value.Sec)*time.Second + time.Duration(value.Nsec), nil
}
