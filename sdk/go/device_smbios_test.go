package orbit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

func smbiosFixture(records ...[]byte) []byte {
	// Windows RawSMBIOSData: calling method, major/minor version, DMI
	// revision, little-endian payload size, then the firmware records.
	data := []byte{0, 2, 6, 0, 0, 0, 0, 0}
	for _, record := range records {
		data = append(data, record...)
	}
	binary.LittleEndian.PutUint32(data[4:8], uint32(len(data)-8))
	return data
}

func smbiosSystemRecord() []byte {
	// Type 1, formatted length 25, handle 1, four string indexes, UUID in
	// SMBIOS 2.6 byte order, wake-up type, then an empty double-NUL string set.
	return []byte{
		1, 25, 1, 0, 0, 0, 0, 0,
		0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		6, 0, 0,
	}
}

func smbiosEndRecord() []byte { return []byte{127, 4, 0xff, 0xff, 0, 0} }

func TestSMBIOSCanonicalUUIDAndFingerprint(t *testing.T) {
	system, end := smbiosSystemRecord(), smbiosEndRecord()
	withStrings := append(append([]byte{}, system[:25]...), []byte("manufacturer\x00model\x00\x00")...)
	extended := append(append([]byte{}, system[:25]...), 1, 2, 0, 0)
	extended[1] = 27
	modern := smbiosFixture(system, end)
	modern[1], modern[2] = 3, 8
	for name, fixture := range map[string][]byte{
		"minimum_version": smbiosFixture(system, end),
		"modern_version":  modern,
		"string_set":      smbiosFixture(withStrings, end),
		"extended_system": smbiosFixture(extended, end),
		"leading_records": smbiosFixture([]byte{0, 4, 2, 0, 'B', 'I', 'O', 'S', 0, 0}, []byte{2, 4, 3, 0, 0, 0}, system, end),
		"trailing_bytes":  smbiosFixture(system, end, []byte{0xff, 1, 2}),
		"trailing_system": smbiosFixture(system, end, system),
	} {
		t.Run(name, func(t *testing.T) {
			identity, err := smbiosSystemUUID(fixture)
			if err != nil || identity != "00112233445566778899aabbccddeeff" {
				t.Fatalf("canonical UUID = %q, %v", identity, err)
			}
			fingerprint, err := MachineFingerprint("app", "test", "windows", identity)
			golden := sha256.Sum256([]byte("orbit-machine-v1\napp\ntest\nwindows\n00112233445566778899aabbccddeeff"))
			if err != nil || fingerprint != hex.EncodeToString(golden[:]) {
				t.Fatalf("Windows fingerprint did not preserve machine_v1 framing: %v", err)
			}
		})
	}
}

func TestSMBIOSRejectsMalformedFirmware(t *testing.T) {
	system, end := smbiosSystemRecord(), smbiosEndRecord()
	valid := smbiosFixture(system, end)
	fixtures := map[string][]byte{
		"empty":                     nil,
		"short_header":              valid[:7],
		"oversized_buffer":          make([]byte, maxSMBIOSBytes+1),
		"empty_payload":             smbiosFixture(),
		"missing_system":            smbiosFixture(end),
		"missing_end":               smbiosFixture(system),
		"duplicate_system":          smbiosFixture(system, system, end),
		"identity_after_end":        smbiosFixture(end, system),
		"truncated_record_header":   smbiosFixture(system, []byte{127, 4, 0}),
		"short_record_length":       smbiosFixture([]byte{0, 3, 0, 0, 0, 0}, system, end),
		"zero_record_length":        smbiosFixture([]byte{0, 0, 0, 0, 0, 0}, system, end),
		"oversized_record_length":   smbiosFixture([]byte{0, 255, 0, 0, 0, 0}, system, end),
		"unterminated_string_set":   smbiosFixture(append(append([]byte{}, system[:25]...), 'x', 0)),
		"missing_string_set":        smbiosFixture(system[:25]),
		"missing_end_strings":       smbiosFixture(system, end[:4]),
		"one_end_string_terminator": smbiosFixture(system, end[:5]),
		"truncated_system_uuid":     smbiosFixture(system[:23]),
		"truncated_payload":         valid[:len(valid)-1],
	}
	for name, version := range map[string][2]byte{"zero_version": {0, 0}, "smbios_1_9": {1, 9}, "smbios_2_5": {2, 5}} {
		fixture := append([]byte{}, valid...)
		fixture[1], fixture[2] = version[0], version[1]
		fixtures[name] = fixture
	}
	for name, declared := range map[string]uint32{"short_declared_payload": uint32(len(valid) - 9), "long_declared_payload": uint32(len(valid) - 7), "overflowing_declared_payload": ^uint32(0)} {
		fixture := append([]byte{}, valid...)
		binary.LittleEndian.PutUint32(fixture[4:8], declared)
		fixtures[name] = fixture
	}
	shortSystem := append(append([]byte{}, system[:24]...), 0, 0)
	shortSystem[1] = 24
	fixtures["short_system_format"] = smbiosFixture(shortSystem, end)
	for name, fill := range map[string]byte{"all_zero_uuid": 0, "all_ones_uuid": 0xff} {
		unavailable := smbiosSystemRecord()
		copy(unavailable[8:24], bytes.Repeat([]byte{fill}, 16))
		fixtures[name] = smbiosFixture(unavailable, end)
	}
	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			identity, err := smbiosSystemUUID(fixture)
			if identity != "" || !errors.Is(err, &Error{Kind: Denied, Code: "device_identity_unavailable"}) {
				t.Fatalf("malformed firmware returned identity=%q, error=%v", identity, err)
			}
		})
	}
}

func TestSMBIOSRejectsEveryTruncatedPrefix(t *testing.T) {
	fixture := smbiosFixture(smbiosSystemRecord(), smbiosEndRecord())
	for size := 0; size < len(fixture); size++ {
		truncated := append([]byte{}, fixture[:size]...)
		if size >= 8 {
			// Adjusting the payload size exercises record validation separately
			// from the raw-table header's exact-size check.
			binary.LittleEndian.PutUint32(truncated[4:8], uint32(size-8))
		}
		if identity, err := smbiosSystemUUID(truncated); identity != "" || !errors.Is(err, errSMBIOSIdentity) {
			t.Fatalf("accepted truncated firmware prefix of length %d", size)
		}
	}
}
