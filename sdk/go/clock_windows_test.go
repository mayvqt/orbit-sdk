//go:build windows

package orbit

import (
	"bufio"
	"math"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func nativeAwakeClock() (time.Duration, error) {
	proc := syscall.NewLazyDLL("api-ms-win-core-realtime-l1-1-1.dll").NewProc("QueryUnbiasedInterruptTimePrecise")
	if err := proc.Find(); err != nil {
		return 0, err
	}
	var ticks uint64
	proc.Call(uintptr(unsafe.Pointer(&ticks)))
	if ticks > math.MaxInt64/100 {
		return 0, ErrClockUncertain
	}
	return time.Duration(ticks) * 100, nil
}

func TestNativeSuspendAdvancesSDKClock(t *testing.T) {
	if os.Getenv("ORBIT_NATIVE_SUSPEND_TEST") != "1" {
		t.Skip("requires actual Windows S3/S4 sleep")
	}
	activeStart := readNativeClock(t, nativeAwakeClock)
	start, err := elapsedClock()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("READY: suspend/hibernate for at least two seconds, then press Enter.")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	end, err := elapsedClock()
	if err != nil {
		t.Fatal(err)
	}
	active := readNativeClock(t, nativeAwakeClock) - activeStart
	elapsed := end - start
	if elapsed-active < time.Second {
		t.Fatal("no actual sleep interval observed")
	}
	t.Logf("SDK elapsed=%s, active elapsed=%s", elapsed, active)
}
