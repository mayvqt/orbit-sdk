//go:build !windows

package orbit

// OpenWindowsStorage fails closed on platforms without current-user Windows DPAPI.
func OpenWindowsStorage(directory string, config Config, device Device) (*WindowsStorage, error) {
	return nil, ErrStorage
}
