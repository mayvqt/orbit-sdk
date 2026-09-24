//go:build windows

package orbit

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func openFixtureWindowsStorage(t *testing.T, directory string) *WindowsStorage {
	t.Helper()
	config, device, _ := storageFixture()
	storage, err := OpenWindowsStorage(directory, config, device)
	if err != nil {
		t.Fatal("native protected storage open failed")
	}
	t.Cleanup(func() { _ = storage.Close() })
	return storage
}

func TestWindowsStoragePersistenceLeaseAndTombstone(t *testing.T) {
	directory := t.TempDir()
	config, device, credential := storageFixture()
	storage := openFixtureWindowsStorage(t, directory)
	if version, value, err := storage.Load(); err != nil || version != 0 || value != nil {
		t.Fatal("new protected storage was not an empty generation zero")
	}
	if err := storage.Save(0, credential); err != nil {
		t.Fatal("native credential save failed")
	}
	data, err := os.ReadFile(filepath.Join(directory, storageDataName))
	if err != nil || bytes.Contains(data, []byte(credential.Credential)) || bytes.Contains(data, []byte(credential.ActivationID)) {
		t.Fatal("protected storage did not contain ciphertext only")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 2 {
		t.Fatal("protected storage left unexpected files")
	}
	if another, err := OpenWindowsStorage(directory, config, device); another != nil || !errors.Is(err, ErrStorage) {
		t.Fatal("simultaneous storage opener bypassed the lifetime lease")
	}
	runStorageChild(t, "locked", directory)
	if storage.Close() != nil {
		t.Fatal("native storage close failed")
	}
	for _, call := range []func() error{
		func() error { _, err := storage.Version(); return err },
		func() error { _, _, err := storage.Load(); return err },
		func() error { return storage.Save(0, credential) },
		func() error { _, err := storage.Invalidate(); return err },
	} {
		if !errors.Is(call(), ErrStorage) {
			t.Fatal("closed native storage remained usable")
		}
	}
	storage = openFixtureWindowsStorage(t, directory)
	if version, value, err := storage.Load(); err != nil || version != 0 || !reflect.DeepEqual(value, &credential) {
		t.Fatal("credential did not survive close and reopen")
	}
	if version, err := storage.Invalidate(); err != nil || version != 1 {
		t.Fatal("native invalidation failed")
	}
	if !errors.Is(storage.Save(0, credential), ErrStaleResponse) {
		t.Fatal("native stale write was accepted")
	}
	_ = storage.Close()
	storage = openFixtureWindowsStorage(t, directory)
	if version, value, err := storage.Load(); err != nil || version != 1 || value != nil {
		t.Fatal("invalidation tombstone did not survive reopen")
	}
}

func TestWindowsStorageRejectsScopeAndCorruptFiles(t *testing.T) {
	for _, change := range []string{"issuer", "application", "environment", "installation", "fingerprint"} {
		t.Run(change, func(t *testing.T) {
			directory := t.TempDir()
			storage := openFixtureWindowsStorage(t, directory)
			_ = storage.Close()
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
			if other, err := OpenWindowsStorage(directory, config, device); other != nil || !errors.Is(err, ErrStorage) {
				t.Fatal("wrong storage scope was accepted")
			}
			_ = openFixtureWindowsStorage(t, directory).Close()
		})
	}
	for _, change := range []string{"tamper", "truncate", "oversize", "empty", "delete", "unknown_version", "extra_field"} {
		t.Run(change, func(t *testing.T) {
			directory := t.TempDir()
			storage := openFixtureWindowsStorage(t, directory)
			_ = storage.Close()
			path := filepath.Join(directory, storageDataName)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("native corruption fixture could not read ciphertext")
			}
			switch change {
			case "tamper":
				data[len(data)-1] ^= 0xff
			case "truncate":
				data = data[:len(data)/2]
			case "oversize":
				data = make([]byte, storageCiphertextLimit+1)
			case "empty":
				data = nil
			case "delete":
				if os.Remove(path) != nil {
					t.Fatal("native missing-file fixture failed")
				}
			case "unknown_version", "extra_field":
				scope := fixtureStorageScope(t)
				plaintext, _ := encodeStorageRecord(scope, 0, nil)
				if change == "unknown_version" {
					plaintext[3] = 2
				} else {
					plaintext = append(plaintext, 1)
				}
				data, err = protectUserData(plaintext, scope.entropy[:])
				clear(plaintext)
				if err != nil {
					t.Fatal("native private-codec fixture protection failed")
				}
			}
			if change != "delete" && os.WriteFile(path, data, 0o600) != nil {
				t.Fatal("native corrupt-file fixture failed")
			}
			config, device, credential := storageFixture()
			if other, err := OpenWindowsStorage(directory, config, device); other != nil || !errors.Is(err, ErrStorage) || strings.Contains(err.Error(), credential.Credential) || strings.Contains(err.Error(), directory) {
				t.Fatal("corrupt storage did not fail closed with a redacted error")
			}
			if change != "delete" {
				current, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(current, data) {
					t.Fatal("opening corrupt storage changed the file")
				}
			} else if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("missing ciphertext was silently reset")
			}
		})
	}
}

func TestWindowsStoragePoisonsAfterFailedAtomicWrite(t *testing.T) {
	directory := t.TempDir()
	storage := openFixtureWindowsStorage(t, directory)
	_, _, credential := storageFixture()
	if storage.Save(0, credential) != nil {
		t.Fatal("native poison fixture save failed")
	}
	// A separate reader denies deletion/replacement while still permitting reads.
	guard, err := openStorageHandle(filepath.Join(directory, storageDataName), syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ, syscall.OPEN_EXISTING, 0)
	if err != nil {
		t.Fatal("native failed-write fixture could not hold the data file")
	}
	if _, err := storage.Invalidate(); !errors.Is(err, ErrStorage) {
		_ = syscall.CloseHandle(guard)
		t.Fatal("blocked atomic replacement was reported successful")
	}
	_ = syscall.CloseHandle(guard)
	if _, err := storage.Version(); !errors.Is(err, ErrStorage) || !errors.Is(storage.Save(0, credential), ErrStorage) {
		t.Fatal("failed native write did not poison the adapter")
	}
	_ = storage.Close()
	reopened := openFixtureWindowsStorage(t, directory)
	if version, value, err := reopened.Load(); err != nil || version != 0 || !reflect.DeepEqual(value, &credential) {
		t.Fatal("failed replacement changed the previously durable record")
	}
}

func TestWindowsStoragePinsDirectoryAncestors(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent")
	directory := filepath.Join(parent, "storage")
	if os.MkdirAll(directory, 0o700) != nil {
		t.Fatal("native pinned-directory fixture failed")
	}
	files, err := openWindowsStorageFiles(directory)
	if err != nil {
		t.Fatal("native directory pin fixture failed")
	}
	defer files.close()
	// The child lease must not mask an ineffective directory pin. Release it
	// independently and mark it closed so fixture cleanup cannot close it twice.
	if syscall.CloseHandle(files.lease) != nil {
		t.Fatal("native directory pin fixture could not release its lease")
	}
	files.lease = syscall.InvalidHandle
	for _, path := range []string{directory, parent} {
		if os.Rename(path, path+"-moved") == nil {
			_ = files.close()
			_ = os.Rename(path+"-moved", path)
			t.Fatal("a directory pin allowed replacement without the child lease")
		}
	}
	if files.close() != nil {
		t.Fatal("native directory pin fixture could not release its pins")
	}
	for _, path := range []string{directory, parent} {
		if os.Rename(path, path+"-moved") != nil {
			t.Fatal("directory remained blocked after releasing all pins")
		}
		if os.Rename(path+"-moved", path) != nil {
			t.Fatal("native renamed directory fixture could not be restored")
		}
	}
	if unsafe.Offsetof(storageRenameInfo{}.directory) != unsafe.Sizeof(uintptr(0)) ||
		unsafe.Offsetof(storageRenameInfo{}.name) != 2*unsafe.Sizeof(uintptr(0))+4 {
		t.Fatal("FILE_RENAME_INFO layout does not match the Windows pointer width")
	}
}

func TestWindowsStorageRejectsNonregularAndReparsePaths(t *testing.T) {
	config, device, _ := storageFixture()
	for _, path := range []string{"relative", `C:relative`, `\\server\share\store`, `\\?\C:\store`} {
		if storage, err := OpenWindowsStorage(path, config, device); storage != nil || err == nil {
			t.Fatal("nonlocal or relative storage path was accepted")
		}
	}
	for _, filename := range []string{storageLockName, storageDataName} {
		t.Run(filename, func(t *testing.T) {
			directory := t.TempDir()
			if os.Mkdir(filepath.Join(directory, filename), 0o700) != nil {
				t.Fatal("nonregular native fixture failed")
			}
			if storage, err := OpenWindowsStorage(directory, config, device); storage != nil || !errors.Is(err, ErrStorage) {
				t.Fatal("nonregular storage file was accepted")
			}
		})
	}
	directory := t.TempDir()
	storage := openFixtureWindowsStorage(t, directory)
	_ = storage.Close()
	if os.Link(filepath.Join(directory, storageDataName), filepath.Join(directory, "alias")) != nil {
		t.Fatal("native hardlink fixture failed")
	}
	if other, err := OpenWindowsStorage(directory, config, device); other != nil || !errors.Is(err, ErrStorage) {
		t.Fatal("hardlinked storage record was accepted")
	}
	parent := t.TempDir()
	target, junction := filepath.Join(parent, "target"), filepath.Join(parent, "junction")
	if os.Mkdir(target, 0o700) != nil || os.Mkdir(junction, 0o700) != nil {
		t.Fatal("native junction fixture directories failed")
	}
	makeStorageJunction(t, junction, target)
	if other, err := OpenWindowsStorage(junction, config, device); other != nil || !errors.Is(err, ErrStorage) {
		t.Fatal("reparse storage directory was accepted")
	}
	if os.Mkdir(filepath.Join(target, "child"), 0o700) != nil {
		t.Fatal("native junction ancestor fixture failed")
	}
	if other, err := OpenWindowsStorage(filepath.Join(junction, "child"), config, device); other != nil || !errors.Is(err, ErrStorage) {
		t.Fatal("reparse storage ancestor was accepted")
	}
}

func makeStorageJunction(t *testing.T, junction, target string) {
	t.Helper()
	substitute, _ := syscall.UTF16FromString(`\??\` + target)
	printName, _ := syscall.UTF16FromString(target)
	buffer := make([]byte, 16+2*(len(substitute)+len(printName)))
	binary.LittleEndian.PutUint32(buffer, 0xa0000003) // IO_REPARSE_TAG_MOUNT_POINT.
	binary.LittleEndian.PutUint16(buffer[4:], uint16(len(buffer)-8))
	binary.LittleEndian.PutUint16(buffer[10:], uint16(2*(len(substitute)-1)))
	binary.LittleEndian.PutUint16(buffer[12:], uint16(2*len(substitute)))
	binary.LittleEndian.PutUint16(buffer[14:], uint16(2*(len(printName)-1)))
	for index, value := range append(substitute, printName...) {
		binary.LittleEndian.PutUint16(buffer[16+index*2:], value)
	}
	handle, err := openStorageHandle(junction, syscall.GENERIC_WRITE, 0, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS)
	if err != nil {
		t.Fatal("native junction fixture handle failed")
	}
	defer syscall.CloseHandle(handle)
	var returned uint32
	if syscall.DeviceIoControl(handle, 0x000900a4, &buffer[0], uint32(len(buffer)), nil, 0, &returned, nil) != nil {
		t.Fatal("native junction creation failed")
	}
}

func runStorageChild(t *testing.T, mode, directory string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsStorageChildProcess$")
	command.Env = append(os.Environ(), "ORBIT_WINDOWS_STORAGE_CHILD="+mode, "ORBIT_WINDOWS_STORAGE_DIRECTORY="+directory)
	if command.Run() != nil {
		t.Fatal("native storage child process failed")
	}
}

func TestWindowsStorageProcessRestart(t *testing.T) {
	directory := t.TempDir()
	runStorageChild(t, "save", directory)
	storage := openFixtureWindowsStorage(t, directory)
	_, _, credential := storageFixture()
	if version, value, err := storage.Load(); err != nil || version != 0 || !reflect.DeepEqual(value, &credential) {
		t.Fatal("successful save did not survive process exit")
	}
	_ = storage.Close()
	runStorageChild(t, "invalidate", directory)
	storage = openFixtureWindowsStorage(t, directory)
	if version, value, err := storage.Load(); err != nil || version != 1 || value != nil {
		t.Fatal("successful invalidation did not survive process exit")
	}
}

func TestWindowsStorageChildProcess(t *testing.T) {
	mode := os.Getenv("ORBIT_WINDOWS_STORAGE_CHILD")
	if mode == "" {
		return
	}
	config, device, credential := storageFixture()
	storage, err := OpenWindowsStorage(os.Getenv("ORBIT_WINDOWS_STORAGE_DIRECTORY"), config, device)
	if mode == "locked" {
		if storage != nil || !errors.Is(err, ErrStorage) {
			t.Fatal("another process bypassed the lifetime lease")
		}
		return
	}
	if err != nil {
		t.Fatal("child process could not acquire released storage")
	}
	switch mode {
	case "save":
		if storage.Save(0, credential) != nil {
			t.Fatal("child process save failed")
		}
	case "invalidate":
		if version, err := storage.Invalidate(); err != nil || version != 1 {
			t.Fatal("child process invalidation failed")
		}
	default:
		t.Fatal("unsupported native storage child fixture")
	}
	// Deliberately omit Close: Windows must release ownership on process exit.
}
