package orbit

import "testing"

func TestMacDirectoryModePolicy(t *testing.T) {
	tests := []struct {
		name        string
		owner       uint32
		mode        uint32
		leaf        bool
		wantAllowed bool
	}{
		{name: "private user leaf", owner: 501, mode: 0700, leaf: true, wantAllowed: true},
		{name: "public user leaf", owner: 501, mode: 0755, leaf: true},
		{name: "root-owned leaf", owner: 0, mode: 0700, leaf: true},
		{name: "root-owned sticky ancestor", owner: 0, mode: 041777, wantAllowed: true},
		{name: "root-owned writable ancestor without sticky", owner: 0, mode: 040777},
		{name: "private user ancestor", owner: 501, mode: 040755, wantAllowed: true},
		{name: "group-writable user ancestor", owner: 501, mode: 040775},
		{name: "foreign-owned ancestor", owner: 502, mode: 040755},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := macDirectoryModeAllowed(test.owner, 501, test.mode, test.leaf); got != test.wantAllowed {
				t.Fatalf("macDirectoryModeAllowed(%d, %d, %#o, %t) = %t, want %t", test.owner, 501, test.mode, test.leaf, got, test.wantAllowed)
			}
		})
	}
}
