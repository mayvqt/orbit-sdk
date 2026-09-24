//go:build windows

package orbit

import (
	"syscall"
	"unsafe"
)

var systemFirmwareTable = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")

// NativeFingerprint reads the SMBIOS system UUID directly from Windows.
func NativeFingerprint(applicationID, environmentID string) (string, error) {
	if !opaque(applicationID) || !opaque(environmentID) {
		return "", ErrConfiguration
	}
	data, err := readSMBIOSTable()
	if err != nil {
		return "", err
	}
	identity, err := smbiosSystemUUID(data)
	if err != nil {
		return "", err
	}
	return MachineFingerprint(applicationID, environmentID, "windows", identity)
}

func readSMBIOSTable() ([]byte, error) {
	if err := systemFirmwareTable.Find(); err != nil {
		return nil, errSMBIOSIdentity
	}
	const rawSMBIOSProvider = 0x52534d42 // RSMB, table zero.
	size, _, _ := systemFirmwareTable.Call(rawSMBIOSProvider, 0, 0, 0)
	if size < rawSMBIOSHeaderSize || size > maxSMBIOSBytes {
		return nil, errSMBIOSIdentity
	}
	buffer := make([]byte, int(size))
	// The synchronous Windows call writes at most len(buffer) bytes. A zero
	// return or changed required size is unavailable; raw errors/IDs stay local.
	written, _, _ := systemFirmwareTable.Call(rawSMBIOSProvider, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	if written != size {
		return nil, errSMBIOSIdentity
	}
	return buffer, nil
}
