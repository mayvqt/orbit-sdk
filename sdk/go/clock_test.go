package orbit

import (
	"errors"
	"testing"
	"time"
)

func TestClockAnchorRejectsRollbackAndIncludesElapsed(t *testing.T) {
	start, err := captureStart()
	if err != nil {
		t.Fatal(err)
	}
	anchor := timeAnchor{server: 1_800_000_000, requestStart: start}
	if start.elapsed >= time.Hour {
		anchor.elapsed -= time.Hour
		anchor.wall -= 3600
		now, err := anchor.now()
		if err != nil || now < anchor.server+3600 {
			t.Fatalf("elapsed time not accounted for: %v", err)
		}
	}
	anchor = timeAnchor{server: 1_800_000_000, requestStart: start}
	anchor.elapsed += time.Hour
	if _, err := anchor.now(); !errors.Is(err, ErrClockUncertain) {
		t.Fatal("future elapsed anchor accepted")
	}
	anchor = timeAnchor{server: 1_800_000_000, requestStart: start}
	anchor.wall += 60
	if _, err := anchor.now(); !errors.Is(err, ErrClockUncertain) {
		t.Fatal("wall rollback accepted")
	}
}

func TestScaleMachTicksChecksTimebaseAndOverflow(t *testing.T) {
	for _, ratio := range [][2]uint32{{0, 1}, {1, 0}} {
		if _, err := scaleMachTicks(1, ratio[0], ratio[1]); !errors.Is(err, ErrClockUncertain) {
			t.Fatalf("accepted invalid timebase %v", ratio)
		}
	}
	value, err := scaleMachTicks(3, 125, 3)
	if err != nil || value != 125*time.Nanosecond {
		t.Fatalf("scaled continuous ticks incorrectly: %v %v", value, err)
	}
	if _, err := scaleMachTicks(^uint64(0), ^uint32(0), 1); !errors.Is(err, ErrClockUncertain) {
		t.Fatal("accepted overflowing continuous time")
	}
}
