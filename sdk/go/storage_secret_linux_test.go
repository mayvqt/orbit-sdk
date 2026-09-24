//go:build linux

package orbit

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestSecretStorageScopeFramingAndBase64Bounds(t *testing.T) {
	scope := fixtureStorageScope(t)
	framed := append([]byte("orbit.sdk.secret-service.v1\x00\x00\x00\x00\x02go"), scope.entropy[:]...)
	framed = append(framed, []byte("\x00\x00\x00\x0b/tmp/scoped")...)
	digest := sha256.Sum256(framed)
	if secretStorageItem(scope, "/tmp/scoped") != hex.EncodeToString(digest[:]) ||
		secretStorageItem(scope, "/tmp/scoped") == secretStorageItem(scope, "/tmp/other") {
		t.Fatal("Secret Service item scope framing changed")
	}
	for _, length := range []int{1, secretRecordLimit} {
		record := bytes.Repeat([]byte{0xab}, length)
		encoded := []byte(base64.StdEncoding.EncodeToString(record))
		for _, suffix := range []string{"", "\n"} {
			decoded, err := decodeSecretOutput(append(bytes.Clone(encoded), suffix...))
			if err != nil || !bytes.Equal(decoded, record) {
				t.Fatal("bounded canonical base64 roundtrip failed")
			}
			clear(decoded)
		}
	}
	for _, output := range [][]byte{nil, []byte("!!!!"), []byte("YR=="), []byte("YQ==\n\n"), []byte("YQ==\r\n"),
		[]byte(" YQ=="), []byte("Y\nQ=="), []byte("YQ"), []byte(base64.StdEncoding.EncodeToString(make([]byte, secretRecordLimit+1)))} {
		if record, err := decodeSecretOutput(output); record != nil || !errors.Is(err, ErrStorage) {
			t.Fatal("noncanonical or oversized Secret Service output was accepted")
		}
	}
	cancelled := false
	output := &secretOutput{limit: 5, cancel: func() { cancelled = true }}
	_, _ = output.Write([]byte("123"))
	_, _ = output.Write([]byte("456789"))
	if !cancelled || !output.overflow || len(output.data) != 5 {
		t.Fatal("bounded helper output did not cancel on overflow")
	}
}

func TestSecretStorageLeaseIdentityAndPermissionsWithoutKeyring(t *testing.T) {
	for _, change := range []string{"directory-mode", "lease-mode", "unlink", "replace", "hardlink", "rename-parent"} {
		t.Run(change, func(t *testing.T) {
			directory := t.TempDir()
			if os.Chmod(directory, 0o700) != nil {
				t.Fatal("synthetic directory privacy setup failed")
			}
			lease, created, err := openSecretStorageLease(directory)
			if err != nil || !created {
				t.Fatal("synthetic private lease initialization failed")
			}
			defer lease.close()
			if other, _, err := openSecretStorageLease(directory); other != nil || !errors.Is(err, ErrStorage) {
				if other != nil {
					_ = other.close()
				}
				t.Fatal("nonblocking lifetime lease permitted a second owner")
			}
			path := filepath.Join(directory, storageLockName)
			switch change {
			case "directory-mode":
				err = os.Chmod(directory, 0o750)
			case "lease-mode":
				err = os.Chmod(path, 0o640)
			case "unlink":
				err = os.Remove(path)
			case "replace":
				if os.Remove(path) != nil {
					t.Fatal("synthetic lease removal failed")
				}
				err = os.WriteFile(path, nil, 0o600)
			case "hardlink":
				err = os.Link(path, filepath.Join(directory, "alias"))
			case "rename-parent":
				moved := directory + "-moved"
				err = os.Rename(directory, moved)
				defer func() { _ = os.Rename(moved, directory) }()
			}
			if err != nil || !errors.Is(lease.check(), ErrStorage) {
				t.Fatal("changed lease identity or privacy remained valid")
			}
		})
	}
	for _, change := range []string{"symlink-directory", "symlink-ancestor", "symlink-lease", "fifo-lease", "directory-lease", "nonempty-lease", "public-directory"} {
		t.Run(change, func(t *testing.T) {
			parent := t.TempDir()
			directory := filepath.Join(parent, "private")
			if os.Mkdir(directory, 0o700) != nil {
				t.Fatal("synthetic private directory creation failed")
			}
			lock := filepath.Join(directory, storageLockName)
			var err error
			switch change {
			case "symlink-directory":
				alias := filepath.Join(parent, "alias")
				err = os.Symlink(directory, alias)
				directory = alias
			case "symlink-ancestor":
				child := filepath.Join(directory, "child")
				if os.Mkdir(child, 0o700) != nil {
					t.Fatal("synthetic ancestor fixture failed")
				}
				alias := filepath.Join(parent, "alias")
				err = os.Symlink(directory, alias)
				directory = filepath.Join(alias, "child")
			case "symlink-lease":
				err = os.Symlink(filepath.Join(parent, "missing"), lock)
			case "fifo-lease":
				err = syscall.Mkfifo(lock, 0o600)
			case "directory-lease":
				err = os.Mkdir(lock, 0o700)
			case "nonempty-lease":
				err = os.WriteFile(lock, []byte("synthetic"), 0o600)
			case "public-directory":
				err = os.Chmod(directory, 0o755)
			}
			if err != nil {
				t.Fatal("synthetic negative lease fixture failed")
			}
			if lease, _, err := openSecretStorageLease(directory); lease != nil || !errors.Is(err, ErrStorage) {
				if lease != nil {
					_ = lease.close()
				}
				t.Fatal("unsafe lease path was accepted")
			}
		})
	}
	if lease, _, err := openSecretStorageLease("relative"); lease != nil || !errors.Is(err, ErrConfiguration) {
		t.Fatal("relative private directory accepted")
	}
	if lease, _, err := openSecretStorageLease("/tmp/" + strings.Repeat("x", 5000)); lease != nil || !errors.Is(err, ErrStorage) {
		t.Fatal("unusable private directory accepted")
	}
}

func TestSecretStoragePendingMarkerRejectsReopenWithoutKeyring(t *testing.T) {
	for _, marker := range [][]byte{{1}, {0}, {1, 1}} {
		directory := t.TempDir()
		if os.Chmod(directory, 0o700) != nil {
			t.Fatal("synthetic pending-marker directory setup failed")
		}
		files, created, err := openSecretStorageLease(directory)
		if err != nil || !created {
			t.Fatal("synthetic pending-marker lease setup failed")
		}
		t.Cleanup(func() { _ = files.close() })
		if files.check() != nil || !errors.Is(files.checkMarker(true), ErrStorage) {
			t.Fatal("empty lease did not require its clean marker state")
		}
		if count, err := files.lease.WriteAt(marker, 0); err != nil || count != len(marker) || files.lease.Sync() != nil {
			t.Fatal("synthetic durable pending-marker setup failed")
		}
		if !errors.Is(files.check(), ErrStorage) {
			t.Fatal("nonempty lease was accepted as clean")
		}
		pendingErr := files.checkMarker(true)
		if bytes.Equal(marker, []byte{1}) && pendingErr != nil || !bytes.Equal(marker, []byte{1}) && !errors.Is(pendingErr, ErrStorage) {
			t.Fatal("pending validation accepted a different marker state")
		}
		if files.close() != nil {
			t.Fatal("synthetic pending-marker lease close failed")
		}
		if other, _, err := openSecretStorageLease(directory); other != nil || !errors.Is(err, ErrStorage) {
			if other != nil {
				_ = other.close()
			}
			t.Fatal("nonempty lease permitted reopening")
		}
		data, err := os.ReadFile(filepath.Join(directory, storageLockName))
		if err != nil || !bytes.Equal(data, marker) {
			t.Fatal("reopening reset or changed the pending marker")
		}
	}
}
