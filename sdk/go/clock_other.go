//go:build !linux && !windows

package orbit

import "time"

func elapsedClock() (time.Duration, error) { return 0, ErrClockUncertain }
