//go:build linux

package orbit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInstalledLinuxRejectsLinksAndInterruptedWrites(t *testing.T) {
	for _, kind := range []string{"directory_symlink", "data_symlink", "data_hardlink", "lease_hardlink", "pending_marker"} {
		t.Run(kind, func(t *testing.T) {
			f := newInstalledFixture(t, true)
			parent := t.TempDir()
			path := filepath.Join(parent, "state")
			c := mustInstalledOpen(t, f, path)
			mustInstalledActivate(t, c)
			_ = c.Close()
			switch kind {
			case "directory_symlink":
				alias := filepath.Join(parent, "alias")
				if err := os.Symlink(path, alias); err != nil {
					t.Fatal(err)
				}
				path = alias
			case "data_symlink":
				name := filepath.Join(path, "orbit-storage.bin")
				moved := filepath.Join(parent, "moved")
				if os.Rename(name, moved) != nil || os.Symlink(moved, name) != nil {
					t.Fatal("fixture setup failed")
				}
			case "data_hardlink":
				if err := os.Link(filepath.Join(path, "orbit-storage.bin"), filepath.Join(parent, "alias")); err != nil {
					t.Fatal(err)
				}
			case "lease_hardlink":
				if err := os.Link(filepath.Join(path, storageLockName), filepath.Join(parent, "alias")); err != nil {
					t.Fatal(err)
				}
			case "pending_marker":
				if err := os.WriteFile(filepath.Join(path, storageLockName), []byte{1}, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if c, err := f.open(path); c != nil || !errors.Is(err, ErrStorage) {
				t.Fatal("unsafe state accepted", err)
			}
		})
	}
}
func TestInstalledAccessDoesNotWriteOnEveryCheck(t *testing.T) {
	f := newInstalledFixture(t, true)
	path := filepath.Join(t.TempDir(), "state")
	c := mustInstalledOpen(t, f, path)
	mustInstalledActivate(t, c)
	name := filepath.Join(path, "orbit-storage.bin")
	before, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	for range 100 {
		if _, err := c.RequireAccess(context.Background(), "export"); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.Stat(name)
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("protected checks rewrote state")
	}
}
func TestInstalledWorkerRespectsRetryAndCloseFailureReleases(t *testing.T) {
	f := newInstalledFixture(t, true)
	path := filepath.Join(t.TempDir(), "state")
	c := mustInstalledOpen(t, f, path)
	mustInstalledActivate(t, c)
	f.mode.Store(1)
	c.mu.Lock()
	c.state.claims.RefreshAfter = c.state.anchor.server - 1
	c.mu.Unlock()
	if _, err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	requests := f.validation.Load()
	time.Sleep(2200 * time.Millisecond)
	if f.validation.Load() != requests {
		t.Fatal("worker bypassed retry deadline")
	}
	// Simulate an unsafe provider change before its mandatory close checkpoint.
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); !errors.Is(err, ErrStorage) {
		t.Fatal("checkpoint failure was hidden", err)
	}
	// Test code alone restores fixture permissions; the SDK never repairs them.
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	f.mode.Store(0)
	c = mustInstalledOpen(t, f, path)
	if _, err := c.RequireAccess(context.Background(), "export"); err != nil {
		t.Fatal("close failure retained the lease", err)
	}
}
