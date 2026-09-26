//go:build windows

package orbit

import (
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

type windowsInstalledFiles struct {
	files    *nativeWindowsStorage
	entropy  []byte
	security *installedWindowsSecurity
}

func openInstalledFiles(path string, entropy []byte) (installedFiles, string, bool, error) {
	security, err := newInstalledWindowsSecurity()
	if err != nil {
		return nil, "", false, err
	}
	pins, err := createInstalledWindowsDirectory(path, security)
	if err != nil {
		security.close()
		return nil, "", false, err
	}
	defer func() {
		for i := len(pins) - 1; i >= 0; i-- {
			syscall.CloseHandle(pins[i])
		}
	}()
	files, err := openWindowsStorageFilesWithSecurity(path, security)
	if err != nil {
		security.close()
		return nil, "", false, err
	}
	return &windowsInstalledFiles{files: files, entropy: append([]byte(nil), entropy...), security: security}, "windows_dpapi", files.allowMissing, nil
}
func createInstalledWindowsDirectory(path string, security *installedWindowsSecurity) (pins []syscall.Handle, err error) {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if !filepath.IsAbs(path) || len(volume) != 2 || volume[1] != ':' || len(path) <= 3 || strings.Contains(path[2:], ":") || !localStorageDrive(volume+`\`) {
		return nil, ErrConfiguration
	}
	held := []syscall.Handle{}
	current := volume + `\`
	defer func() {
		if err != nil {
			for i := len(held) - 1; i >= 0; i-- {
				syscall.CloseHandle(held[i])
			}
		}
	}()
	parts := strings.Split(path[3:], `\`)
	paths := []string{current}
	for _, part := range parts {
		if part == "" || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return nil, ErrConfiguration
		}
		current = filepath.Join(current, part)
		paths = append(paths, current)
	}
	for i, name := range paths {
		handle, err := openStorageHandle(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS)
		created := false
		if err == syscall.ERROR_PATH_NOT_FOUND || err == syscall.ERROR_FILE_NOT_FOUND {
			if security.mkdir(name) != nil {
				return nil, ErrStorage
			}
			created = true
			handle, err = openStorageHandle(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS)
		}
		if err != nil {
			return nil, ErrStorage
		}
		held = append(held, handle)
		if _, err := storageHandleInfo(handle, true); err != nil {
			return nil, ErrStorage
		}
		if (created || i == len(paths)-1) && security.check(handle) != nil {
			return nil, ErrStorage
		}
	}
	return held, nil
}
func (s *windowsInstalledFiles) check() error { return s.files.checkDirectories() }
func (s *windowsInstalledFiles) read() ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if rejectInstalledImpersonation() != nil {
		return nil, ErrStorage
	}
	data, err := s.files.ciphertext()
	if err != nil {
		return nil, err
	}
	return transformUserData(userUnprotectProc, data, s.entropy, installedLimit)
}
func (s *windowsInstalledFiles) write(data []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if rejectInstalledImpersonation() != nil {
		return ErrStorage
	}
	if len(data) > installedLimit {
		return ErrStorage
	}
	ciphertext, err := transformUserData(userProtectProc, data, s.entropy, installedLimit*2)
	if err != nil {
		return ErrStorage
	}
	return s.files.writeCiphertext(ciphertext)
}
func (s *windowsInstalledFiles) close() error {
	err := s.files.close()
	s.security.close()
	clear(s.entropy)
	return err
}
