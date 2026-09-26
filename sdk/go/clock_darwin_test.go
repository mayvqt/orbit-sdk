//go:build darwin && cgo

package orbit

/*
#include "macos_native.h"
*/
import "C"

import (
	"bufio"
	"os"
	"testing"
	"time"
)

func nativeAwakeClock() (time.Duration, error) {
	var numerator, denominator C.uint32_t
	if C.orbit_mach_timebase(&numerator, &denominator) != 0 {
		return 0, ErrClockUncertain
	}
	return scaleMachTicks(
		uint64(C.orbit_mach_awake_time()),
		uint32(numerator),
		uint32(denominator),
	)
}

func TestNativeSuspendAdvancesSDKClock(t *testing.T) {
	if os.Getenv("ORBIT_NATIVE_SUSPEND_TEST") != "1" {
		t.Skip("requires actual macOS sleep")
	}
	activeStart, err := nativeAwakeClock()
	if err != nil {
		t.Fatal(err)
	}
	start, err := elapsedClock()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("READY: sleep for at least two seconds, then press Enter.")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	end, err := elapsedClock()
	if err != nil {
		t.Fatal(err)
	}
	activeEnd, err := nativeAwakeClock()
	if err != nil {
		t.Fatal(err)
	}
	if end-start-(activeEnd-activeStart) < time.Second {
		t.Fatal("no actual sleep interval observed")
	}
	t.Logf("SDK elapsed=%s, active elapsed=%s", end-start, activeEnd-activeStart)
}
