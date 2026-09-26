//go:build windows

package orbit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestInstalledWindowsPrivateACLAndDPAPI(t *testing.T) {
	f := newInstalledFixture(t, true)
	path := filepath.Join(t.TempDir(), "state")
	c := mustInstalledOpen(t, f, path)
	mustInstalledActivate(t, c)
	files := c.installed.files.(*windowsInstalledFiles)
	for _, name := range []string{storageLockName, storageDataName} {
		if name == storageLockName {
			if files.security.check(files.files.lease) != nil {
				t.Fatal("lease DACL is not private")
			}
			continue
		}
		handle, err := openStorageHandle(filepath.Join(path, name), syscall.GENERIC_READ, syscall.FILE_SHARE_READ, syscall.OPEN_EXISTING, 0)
		if err != nil {
			t.Fatal(err)
		}
		if files.security.check(handle) != nil {
			t.Fatal("data DACL is not private")
		}
		syscall.CloseHandle(handle)
	}
	data, err := os.ReadFile(filepath.Join(path, storageDataName))
	if err != nil || bytes.Contains(data, []byte("orbit.installed-client")) || bytes.Contains(data, []byte("synthetic-key")) {
		t.Fatal("installed data was not DPAPI-protected")
	}
	if other, err := f.open(path); other != nil || !errors.Is(err, ErrInstallationInUse) {
		t.Fatal("exclusive installed Windows lease failed", err)
	}
}
func TestInstalledWindowsRejectsUnsafeExistingLeaf(t *testing.T) {
	f := newInstalledFixture(t, true)
	path := t.TempDir() // Inherited, unprotected DACL; the SDK must not repair it.
	if c, err := f.open(path); c != nil || !errors.Is(err, ErrStorage) {
		t.Fatal("unsafe inherited DACL accepted", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatal("unsafe directory was changed")
	}
}

func TestInstalledWindowsRejectsThreadImpersonation(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	impersonate := installedAdvapi.NewProc("ImpersonateSelf")
	revert := installedAdvapi.NewProc("RevertToSelf")
	ok, _, _ := impersonate.Call(2)
	if ok == 0 {
		t.Fatal("impersonation fixture unavailable")
	}
	defer revert.Call()
	if security, err := newInstalledWindowsSecurity(); security != nil || !errors.Is(err, ErrStorage) {
		t.Fatal("impersonated thread opened installed storage", err)
	}
}
