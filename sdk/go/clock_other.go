//go:build !linux && !windows && !darwin

package orbit

import "time"

func elapsedClock() (time.Duration, error) { return 0, ErrClockUncertain }
