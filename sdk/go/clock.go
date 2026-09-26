package orbit

import (
	"math"
	"math/bits"
	"time"
)

func scaleMachTicks(ticks uint64, numerator, denominator uint32) (time.Duration, error) {
	if numerator == 0 || denominator == 0 {
		return 0, ErrClockUncertain
	}
	hi, lo := bits.Mul64(ticks, uint64(numerator))
	if hi >= uint64(denominator) {
		return 0, ErrClockUncertain
	}
	nanoseconds, _ := bits.Div64(hi, lo, uint64(denominator))
	if nanoseconds > math.MaxInt64 {
		return 0, ErrClockUncertain
	}
	return time.Duration(nanoseconds), nil
}

type requestStart struct {
	elapsed time.Duration
	wall    int64
}
type timeAnchor struct {
	server int64
	requestStart
}

func captureStart() (requestStart, error) {
	elapsed, err := elapsedClock()
	if err != nil {
		return requestStart{}, err
	}
	wall := time.Now().Unix()
	if wall < 0 {
		return requestStart{}, ErrClockUncertain
	}
	return requestStart{elapsed: elapsed, wall: wall}, nil
}
func (a timeAnchor) now() (int64, error) {
	elapsed, err := elapsedClock()
	if err != nil || elapsed < a.elapsed {
		return 0, ErrClockUncertain
	}
	seconds := int64((elapsed - a.elapsed) / time.Second)
	if a.wall > math.MaxInt64-seconds || a.server > math.MaxInt64-seconds {
		return 0, ErrClockUncertain
	}
	difference := time.Now().Unix() - (a.wall + seconds)
	if difference < -30 || difference > 30 {
		return 0, ErrClockUncertain
	}
	return a.server + seconds, nil
}

func timestamp(value string) (int64, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Nanosecond() != 0 {
		return 0, ErrInvalidResponse
	}
	return parsed.Unix(), nil
}
