//go:build linux

package orbit

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func nativeSecretFixture(t *testing.T) string {
	t.Helper()
	if os.Getenv("ORBIT_NATIVE_STORAGE_TEST") != "1" {
		t.Skip("isolated Secret Service fixture required")
	}
	root := os.Getenv("ORBIT_KEYRING_FIXTURE")
	var info syscall.Stat_t
	if !filepath.IsAbs(root) || syscall.Lstat(root, &info) != nil || info.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		info.Mode&0o077 != 0 || info.Uid != uint32(os.Geteuid()) || os.Geteuid() == 0 ||
		os.Getenv("XDG_DATA_HOME") != filepath.Join(root, "data") ||
		os.Getenv("XDG_RUNTIME_DIR") != filepath.Join(root, "runtime") ||
		os.Getenv("GNOME_KEYRING_CONTROL") != filepath.Join(root, "control") || os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Fatal("native Secret Service tests require the private isolated keyring harness")
	}
	return root
}

func nativeSecretDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp(nativeSecretFixture(t), "go-storage-")
	if err != nil {
		t.Fatal("private native storage directory creation failed")
	}
	t.Cleanup(func() {
		if os.RemoveAll(directory) != nil {
			t.Error("private native storage fixture cleanup failed")
		}
	})
	return directory
}

func openNativeSecretStorage(t *testing.T, directory string) *SecretServiceStorage {
	t.Helper()
	config, device, _ := storageFixture()
	storage, err := OpenSecretServiceStorage(directory, config, device)
	if err != nil {
		t.Fatal("isolated Secret Service storage open failed")
	}
	t.Cleanup(func() { _ = storage.Close() })
	return storage
}

func denyNativeSecretStorage(t *testing.T, directory string, config Config, device Device) {
	t.Helper()
	storage, err := OpenSecretServiceStorage(directory, config, device)
	if storage != nil {
		_ = storage.Close()
		t.Fatal("invalid keyring state was accepted")
	}
	_, _, credential := storageFixture()
	if !errors.Is(err, ErrStorage) || strings.Contains(err.Error(), credential.Credential) || strings.Contains(err.Error(), directory) {
		t.Fatal("invalid keyring state did not fail with a redacted error")
	}
}

func TestNativeSecretServiceReopenLeaseTombstoneAndPrivateFiles(t *testing.T) {
	directory := nativeSecretDirectory(t)
	config, device, credential := storageFixture()
	storage := openNativeSecretStorage(t, directory)
	if version, value, err := storage.Load(); err != nil || version != 0 || value != nil {
		t.Fatal("fresh keyring item was not a generation zero tombstone")
	}
	if storage.Save(0, credential) != nil {
		t.Fatal("native keyring save failed")
	}
	if other, err := OpenSecretServiceStorage(directory, config, device); other != nil || !errors.Is(err, ErrStorage) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("native keyring lifetime lease allowed another owner")
	}
	runSecretChild(t, "locked", directory)
	entries, err := os.ReadDir(directory)
	var lease syscall.Stat_t
	if err != nil || len(entries) != 1 || entries[0].Name() != storageLockName ||
		syscall.Lstat(filepath.Join(directory, storageLockName), &lease) != nil || lease.Size != 0 || lease.Mode&0o777 != 0o600 {
		t.Fatal("native protected storage left unexpected or nonprivate files")
	}
	if storage.Close() != nil || storage.Close() != nil {
		t.Fatal("native keyring close failed")
	}
	if _, err := storage.Version(); !errors.Is(err, ErrStorage) {
		t.Fatal("closed keyring storage stayed usable")
	}
	storage = openNativeSecretStorage(t, directory)
	if version, value, err := storage.Load(); err != nil || version != 0 || !reflect.DeepEqual(value, &credential) {
		t.Fatal("keyring credential did not survive reopen")
	}
	if version, err := storage.Invalidate(); err != nil || version != 1 {
		t.Fatal("keyring invalidation did not advance generation")
	}
	var writers sync.WaitGroup
	for i := 0; i < 12; i++ {
		writers.Go(func() {
			if !errors.Is(storage.Save(0, credential), ErrStaleResponse) {
				t.Error("stale writer replaced keyring tombstone")
			}
		})
	}
	writers.Wait()
	_ = storage.Close()
	storage = openNativeSecretStorage(t, directory)
	if version, value, err := storage.Load(); err != nil || version != 1 || value != nil {
		t.Fatal("keyring tombstone did not survive reopen")
	}
	// The fixture's actual encrypted collection must not expose the private
	// record or its base64 representation after a completed native save.
	keys, err := os.ReadDir(filepath.Join(nativeSecretFixture(t), "data", "keyrings"))
	if err != nil {
		t.Fatal("isolated encrypted keyring evidence is missing")
	}
	found := false
	scope := fixtureStorageScope(t)
	record, _ := encodeStorageRecord(scope, 0, &credential)
	encoded := []byte(base64.StdEncoding.EncodeToString(record))
	defer clear(record)
	defer clear(encoded)
	for _, key := range keys {
		if !strings.HasSuffix(key.Name(), ".keyring") {
			continue
		}
		found = true
		file, err := os.Open(filepath.Join(nativeSecretFixture(t), "data", "keyrings", key.Name()))
		if err != nil {
			t.Fatal("isolated keyring file is unreadable")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 1024*1024+1))
		_ = file.Close()
		if readErr != nil || len(data) > 1024*1024 || !bytes.HasPrefix(data, []byte("GnomeKeyring\n\r\x00\n")) ||
			bytes.Contains(data, []byte(credential.Credential)) || bytes.Contains(data, record) || bytes.Contains(data, encoded) {
			t.Fatal("native fixture did not retain the credential only in its encrypted keyring")
		}
	}
	if !found {
		t.Fatal("isolated encrypted keyring evidence is missing")
	}
}

func runSecretChild(t *testing.T, mode, directory string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeSecretServiceChild$")
	command.Env = append(os.Environ(), "ORBIT_GO_SECRET_CHILD="+mode, "ORBIT_GO_SECRET_DIRECTORY="+directory)
	if command.Run() != nil {
		t.Fatal("isolated keyring child process failed")
	}
}

func TestNativeSecretServiceProcessExit(t *testing.T) {
	directory := nativeSecretDirectory(t)
	runSecretChild(t, "save", directory)
	storage := openNativeSecretStorage(t, directory)
	_, _, credential := storageFixture()
	if version, value, err := storage.Load(); err != nil || version != 0 || !reflect.DeepEqual(value, &credential) {
		t.Fatal("keyring save did not survive process exit")
	}
	_ = storage.Close()
	runSecretChild(t, "invalidate", directory)
	storage = openNativeSecretStorage(t, directory)
	if version, value, err := storage.Load(); err != nil || version != 1 || value != nil {
		t.Fatal("keyring invalidation did not survive process exit")
	}
}

func TestNativeSecretServiceChild(t *testing.T) {
	mode := os.Getenv("ORBIT_GO_SECRET_CHILD")
	if mode == "" {
		return
	}
	root := nativeSecretFixture(t)
	directory := os.Getenv("ORBIT_GO_SECRET_DIRECTORY")
	relative, err := filepath.Rel(root, directory)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
		t.Fatal("native child directory is outside its fixture")
	}
	config, device, credential := storageFixture()
	storage, err := OpenSecretServiceStorage(directory, config, device)
	if mode == "locked" {
		if storage != nil {
			_ = storage.Close()
		}
		if storage != nil || !errors.Is(err, ErrStorage) {
			t.Fatal("another process bypassed the keyring lease")
		}
		return
	}
	if err != nil {
		t.Fatal("native child could not open released keyring storage")
	}
	switch mode {
	case "save":
		if storage.Save(0, credential) != nil {
			t.Fatal("native child keyring save failed")
		}
	case "invalidate":
		if generation, err := storage.Invalidate(); err != nil || generation != 1 {
			t.Fatal("native child keyring invalidation failed")
		}
	default:
		t.Fatal("unknown native child fixture mode")
	}
	// Deliberately omit Close to test OS lease release at process exit.
}

func seedNativeSecret(t *testing.T, operation, item string, data []byte) {
	t.Helper()
	nativeSecretFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), secretCommandDeadline)
	defer cancel()
	arguments := []string{operation}
	if operation == "store" {
		arguments = append(arguments, "--label=Orbit SDK synthetic fixture")
	}
	arguments = append(arguments, "application", "orbit-sdk", "sdk", "go", "scope", item)
	command := exec.CommandContext(ctx, "/usr/bin/secret-tool", arguments...)
	command.Stdin = bytes.NewReader(data)
	if command.Run() != nil {
		t.Fatal("synthetic keyring record setup failed")
	}
}

func TestNativeSecretServiceRejectsScopeCorruptAndMissingItems(t *testing.T) {
	nativeSecretFixture(t)
	for _, change := range []string{"issuer", "application", "environment", "installation", "fingerprint"} {
		t.Run(change, func(t *testing.T) {
			directory := nativeSecretDirectory(t)
			_ = openNativeSecretStorage(t, directory).Close()
			config, device, _ := storageFixture()
			switch change {
			case "issuer":
				config.Issuer += "other"
			case "application":
				config.ApplicationID += "other"
			case "environment":
				config.EnvironmentID += "other"
			case "installation":
				device.InstallationID += "other"
			case "fingerprint":
				fingerprint, provider := strings.Repeat("a", 64), "machine_v1"
				device.Fingerprint, device.FingerprintProvider = &fingerprint, &provider
			}
			denyNativeSecretStorage(t, directory, config, device)
			_ = openNativeSecretStorage(t, directory).Close()
		})
	}
	for _, change := range []string{"missing", "empty", "invalid-base64", "oversize", "truncated", "format", "trailing", "wrong-record-scope"} {
		t.Run(change, func(t *testing.T) {
			directory := nativeSecretDirectory(t)
			_ = openNativeSecretStorage(t, directory).Close()
			scope := fixtureStorageScope(t)
			item := secretStorageItem(scope, directory)
			record, _ := encodeStorageRecord(scope, 0, nil)
			defer clear(record)
			switch change {
			case "format":
				record[3] = 255
			case "trailing":
				record = append(record, 1)
			case "truncated":
				record = record[:len(record)-1]
			case "wrong-record-scope":
				scope.config.Issuer += "other"
				record, _ = encodeStorageRecord(scope, 0, nil)
			}
			encoded := []byte(base64.StdEncoding.EncodeToString(record))
			switch change {
			case "empty":
				encoded = nil
			case "invalid-base64":
				encoded = []byte("synthetic-invalid-base64")
			case "oversize":
				encoded = bytes.Repeat([]byte("A"), secretBase64Limit+2)
			}
			if change == "missing" {
				seedNativeSecret(t, "clear", item, nil)
			} else {
				seedNativeSecret(t, "store", item, encoded)
			}
			clear(encoded)
			config, device, _ := storageFixture()
			denyNativeSecretStorage(t, directory, config, device)
			if change == "missing" {
				if _, err := lookupSecretRecord(item); err != errStorageMissing {
					t.Fatal("missing keyring item was silently reset")
				}
			}
		})
	}
	directory := nativeSecretDirectory(t)
	if os.WriteFile(filepath.Join(directory, storageLockName), nil, 0o600) != nil {
		t.Fatal("interrupted initialization fixture failed")
	}
	config, device, _ := storageFixture()
	denyNativeSecretStorage(t, directory, config, device)
	other := nativeSecretDirectory(t)
	if storage := openNativeSecretStorage(t, other); storage.Close() != nil {
		t.Fatal("independent directory could not initialize its own item")
	}
}

func TestNativeSecretServiceHelperFailureAndDeadlinePoison(t *testing.T) {
	root := nativeSecretFixture(t)
	for _, failure := range []string{"unavailable", "deadline"} {
		t.Run(failure, func(t *testing.T) {
			directory := nativeSecretDirectory(t)
			storage := openNativeSecretStorage(t, directory)
			_, _, credential := storageFixture()
			if storage.Save(0, credential) != nil {
				t.Fatal("native failure fixture save failed")
			}
			oldBus := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
			path := filepath.Join(directory, "unavailable-bus")
			if failure == "deadline" {
				path = filepath.Join(directory, "blocked-bus")
				listener, err := net.Listen("unix", path)
				if err != nil {
					t.Fatal("synthetic blocked bus creation failed")
				}
				var connections sync.WaitGroup
				stop := make(chan struct{})
				done := make(chan struct{})
				go func() {
					defer close(done)
					for {
						connection, err := listener.Accept()
						if err != nil {
							return
						}
						connections.Go(func() {
							defer connection.Close()
							_ = connection.SetReadDeadline(time.Now().Add(8 * time.Second))
							select {
							case <-stop:
								return
							default:
							}
							_, _ = io.Copy(io.Discard, connection)
						})
					}
				}()
				t.Cleanup(func() { close(stop); _ = listener.Close(); <-done; connections.Wait() })
			}
			t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+path)
			if version, value, err := storage.Load(); err != nil || version != 0 || !reflect.DeepEqual(value, &credential) {
				t.Fatal("cached keyring reads unexpectedly spawned a helper")
			}
			started := time.Now()
			err := storage.Save(0, credential)
			elapsed := time.Since(started)
			if !errors.Is(err, ErrStorage) || elapsed > 7*time.Second || failure == "deadline" && elapsed < 4*time.Second ||
				strings.Contains(err.Error(), credential.Credential) || strings.Contains(err.Error(), root) {
				t.Fatal("keyring helper failure was unbounded or unredacted")
			}
			if _, err := storage.Version(); !errors.Is(err, ErrStorage) {
				t.Fatal("failed keyring write did not poison the adapter")
			}
			_ = storage.Close()
			if os.Setenv("DBUS_SESSION_BUS_ADDRESS", oldBus) != nil {
				t.Fatal("synthetic bus restoration failed")
			}
			marker, err := os.ReadFile(filepath.Join(directory, storageLockName))
			if err != nil || !bytes.Equal(marker, []byte{1}) {
				t.Fatal("failed keyring invocation did not retain its pending marker")
			}
			config, device, _ := storageFixture()
			denyNativeSecretStorage(t, directory, config, device)
			marker, err = os.ReadFile(filepath.Join(directory, storageLockName))
			if err != nil || !bytes.Equal(marker, []byte{1}) {
				t.Fatal("reopening a failed store changed its pending marker")
			}
		})
	}
}

func TestNativeSecretServicePendingMarkerBlocksValidRecord(t *testing.T) {
	directory := nativeSecretDirectory(t)
	storage := openNativeSecretStorage(t, directory)
	config, device, credential := storageFixture()
	if storage.Save(0, credential) != nil || storage.Close() != nil {
		t.Fatal("native pending-marker credential setup failed")
	}
	files, created, err := openSecretStorageLease(directory)
	if err != nil || created {
		t.Fatal("native pending-marker lease setup failed")
	}
	t.Cleanup(func() { _ = files.close() })
	if count, err := files.lease.WriteAt([]byte{1}, 0); err != nil || count != 1 || files.lease.Sync() != nil || files.close() != nil {
		t.Fatal("native pending-marker persistence failed")
	}
	denyNativeSecretStorage(t, directory, config, device)
	marker, err := os.ReadFile(filepath.Join(directory, storageLockName))
	if err != nil || !bytes.Equal(marker, []byte{1}) {
		t.Fatal("native pending-marker denial reset the fence")
	}
	// Recover through a distinct item and fresh online activation context;
	// reopening or deleting the old lease must never be automatic recovery.
	fresh := openNativeSecretStorage(t, nativeSecretDirectory(t))
	if version, value, err := fresh.Load(); err != nil || version != 0 || value != nil {
		t.Fatal("new recovery directory did not begin without cached access")
	}
}

func TestNativeSecretServiceGenerationLimitAndPermissionChanges(t *testing.T) {
	directory := nativeSecretDirectory(t)
	storage := openNativeSecretStorage(t, directory)
	_ = storage.Close()
	scope := fixtureStorageScope(t)
	record, _ := encodeStorageRecord(scope, math.MaxInt64, nil)
	if storeSecretRecord(secretStorageItem(scope, directory), record) != nil {
		t.Fatal("generation-bound fixture setup failed")
	}
	clear(record)
	storage = openNativeSecretStorage(t, directory)
	if _, err := storage.Invalidate(); !errors.Is(err, ErrStorage) {
		t.Fatal("keyring generation overflow was accepted")
	}
	if _, err := storage.Version(); !errors.Is(err, ErrStorage) {
		t.Fatal("generation overflow did not poison keyring storage")
	}
	_ = storage.Close()
	storage = openNativeSecretStorage(t, directory)
	if version, err := storage.Version(); err != nil || version != math.MaxInt64 {
		t.Fatal("failed keyring invalidation changed generation")
	}
	if os.Chmod(filepath.Join(directory, storageLockName), 0o640) != nil {
		t.Fatal("native permission fixture failed")
	}
	if _, _, err := storage.Load(); !errors.Is(err, ErrStorage) {
		t.Fatal("keyring storage ignored weakened lease permissions")
	}
}
