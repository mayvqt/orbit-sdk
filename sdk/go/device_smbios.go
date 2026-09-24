package orbit

import (
	"encoding/binary"
	"encoding/hex"
)

const rawSMBIOSHeaderSize = 8
const maxSMBIOSBytes = 1 << 20

var errSMBIOSIdentity = &Error{Kind: Denied, Code: "device_identity_unavailable"}

// smbiosSystemUUID reads Windows RawSMBIOSData without retaining the raw table.
// SMBIOS 2.6 defines the first three UUID fields as little endian; older tables
// are ambiguous and must not silently select a different machine identity.
func smbiosSystemUUID(data []byte) (string, error) {
	if len(data) < rawSMBIOSHeaderSize || len(data) > maxSMBIOSBytes {
		return "", errSMBIOSIdentity
	}
	if data[1] < 2 || data[1] == 2 && data[2] < 6 || binary.LittleEndian.Uint32(data[4:8]) != uint32(len(data)-rawSMBIOSHeaderSize) {
		return "", errSMBIOSIdentity
	}
	var identity string
	for offset := rawSMBIOSHeaderSize; offset < len(data); {
		if len(data)-offset < 4 {
			return "", errSMBIOSIdentity
		}
		recordType, formattedLength := data[offset], int(data[offset+1])
		if formattedLength < 4 || formattedLength > len(data)-offset {
			return "", errSMBIOSIdentity
		}
		end := offset + formattedLength
		for end+1 < len(data) && (data[end] != 0 || data[end+1] != 0) {
			end++
		}
		if end+1 >= len(data) {
			return "", errSMBIOSIdentity
		}
		switch recordType {
		case 1:
			if identity != "" || formattedLength < 25 {
				return "", errSMBIOSIdentity
			}
			uuid := [16]byte{}
			copy(uuid[:], data[offset+8:offset+24])
			uuid[0], uuid[1], uuid[2], uuid[3] = uuid[3], uuid[2], uuid[1], uuid[0]
			uuid[4], uuid[5] = uuid[5], uuid[4]
			uuid[6], uuid[7] = uuid[7], uuid[6]
			identity = hex.EncodeToString(uuid[:])
			if identity == "00000000000000000000000000000000" || identity == "ffffffffffffffffffffffffffffffff" {
				return "", errSMBIOSIdentity
			}
		case 127:
			if identity == "" {
				return "", errSMBIOSIdentity
			}
			return identity, nil
		}
		offset = end + 2
	}
	return "", errSMBIOSIdentity
}
