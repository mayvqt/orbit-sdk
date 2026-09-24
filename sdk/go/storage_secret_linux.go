//go:build linux

package orbit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf8"
)

type secretDirectory struct {
	path string
	file *os.File
}

type nativeSecretStorage struct {
	directory   string
	directories []secretDirectory
	lease       *os.File
	item        string
	version     uint64
	credential  *StoredCredential
}

// OpenSecretServiceStorage opens an existing absolute private Linux directory
// for one scope. It never unlocks the keyring or resets missing/corrupt state.
func OpenSecretServiceStorage(directory string, config Config, device Device) (*SecretServiceStorage, error) {
	scope, err := newStorageScope(config, device)
	if err != nil {
		return nil, err
	}
	initial, err := encodeStorageRecord(scope, 0, nil)
	if err != nil {
		return nil, ErrStorage
	}
	valid := len(initial) <= secretRecordLimit
	clear(initial)
	if !valid {
		return nil, ErrStorage
	}
	files, created, err := openSecretStorageLease(directory)
	if err != nil {
		return nil, err
	}
	files.item = secretStorageItem(scope, files.directory)
	record, err := lookupSecretRecord(files.item)
	if err == errStorageMissing && created {
		err = files.write(scope, 0, nil)
	} else if err == nil {
		files.version, files.credential, err = decodeStorageRecord(scope, record)
	}
	clear(record)
	runtime.KeepAlive(record)
	if err != nil || files.check() != nil {
		_ = files.close()
		return nil, ErrStorage
	}
	return &SecretServiceStorage{state: &protectedStorageState{files: files, scope: scope}}, nil
}

func secretStorageItem(scope storageScope, directory string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("orbit.sdk.secret-service.v1\x00"))
	frame := func(value string) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	frame("go")
	_, _ = hash.Write(scope.entropy[:])
	frame(directory)
	return hex.EncodeToString(hash.Sum(nil))
}

func openSecretStorageLease(directory string) (_ *nativeSecretStorage, created bool, err error) {
	if !filepath.IsAbs(directory) || strings.ContainsRune(directory, 0) || !utf8.ValidString(directory) {
		return nil, false, ErrConfiguration
	}
	directory = filepath.Clean(directory)
	files := &nativeSecretStorage{directory: directory}
	defer func() {
		if err != nil {
			_ = files.close()
		}
	}()
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	descriptor, openErr := syscall.Open("/", flags, 0)
	if openErr != nil {
		return nil, false, ErrStorage
	}
	files.directories = append(files.directories, secretDirectory{"/", os.NewFile(uintptr(descriptor), "Orbit storage directory")})
	current := "/"
	for _, component := range strings.Split(strings.TrimPrefix(directory, "/"), "/") {
		if component == "" {
			continue
		}
		descriptor, openErr = syscall.Openat(descriptor, component, flags, 0)
		if openErr != nil {
			return nil, false, ErrStorage
		}
		current = filepath.Join(current, component)
		files.directories = append(files.directories, secretDirectory{current, os.NewFile(uintptr(descriptor), "Orbit storage directory")})
	}
	if files.checkDirectories() != nil {
		return nil, false, ErrStorage
	}
	lockFlags := syscall.O_RDWR | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	lock, openErr := syscall.Openat(descriptor, storageLockName, lockFlags|syscall.O_CREAT|syscall.O_EXCL, 0o600)
	created = openErr == nil
	if openErr == syscall.EEXIST {
		lock, openErr = syscall.Openat(descriptor, storageLockName, lockFlags, 0)
	}
	if openErr != nil {
		return nil, false, ErrStorage
	}
	files.lease = os.NewFile(uintptr(lock), "Orbit storage lease")
	if syscall.Flock(lock, syscall.LOCK_EX|syscall.LOCK_NB) != nil || files.check() != nil {
		return nil, false, ErrStorage
	}
	if created && (files.lease.Sync() != nil || files.directories[len(files.directories)-1].file.Sync() != nil) {
		return nil, false, ErrStorage
	}
	return files, created, nil
}

func secretFileIdentity(file *os.File, path string, directory, private bool) error {
	var opened, named syscall.Stat_t
	if file == nil || syscall.Fstat(int(file.Fd()), &opened) != nil || syscall.Lstat(path, &named) != nil {
		return ErrStorage
	}
	kind := uint32(syscall.S_IFREG)
	if directory {
		kind = syscall.S_IFDIR
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino || opened.Mode&syscall.S_IFMT != kind ||
		named.Mode&syscall.S_IFMT != kind || opened.Nlink == 0 || !directory && opened.Nlink != 1 ||
		private && (opened.Uid != uint32(os.Geteuid()) || opened.Mode&0o077 != 0) {
		return ErrStorage
	}
	return nil
}

func (s *nativeSecretStorage) checkDirectories() error {
	if len(s.directories) == 0 {
		return ErrStorage
	}
	for index, directory := range s.directories {
		if secretFileIdentity(directory.file, directory.path, true, index == len(s.directories)-1) != nil {
			return ErrStorage
		}
	}
	return nil
}

func (s *nativeSecretStorage) check() error {
	return s.checkMarker(false)
}

func (s *nativeSecretStorage) checkMarker(pending bool) error {
	if s.checkDirectories() != nil {
		return ErrStorage
	}
	if secretFileIdentity(s.lease, filepath.Join(s.directory, storageLockName), false, true) != nil {
		return ErrStorage
	}
	// Only the explicitly expected state is valid: empty when idle, exactly one
	// 0x01 byte while a store is in flight. Never accept arbitrary nonempty data.
	var marker [2]byte
	count, err := s.lease.ReadAt(marker[:], 0)
	if err != io.EOF || !pending && count != 0 || pending && (count != 1 || marker[0] != 1) {
		return ErrStorage
	}
	return nil
}

func (s *nativeSecretStorage) read(storageScope) (uint64, *StoredCredential, error) {
	if s.check() != nil {
		return 0, nil, ErrStorage
	}
	return s.version, cloneCredential(s.credential), nil
}

func (s *nativeSecretStorage) write(scope storageScope, version uint64, credential *StoredCredential) error {
	if s.check() != nil {
		return ErrStorage
	}
	record, err := encodeStorageRecord(scope, version, credential)
	if err != nil {
		return ErrStorage
	}
	defer func() { clear(record); runtime.KeepAlive(record) }()
	if len(record) > secretRecordLimit {
		return ErrStorage
	}
	// A DBus store may outlive this process and its CLOEXEC lease. Make that
	// uncertainty durable before invoking the helper, including initialization.
	if count, err := s.lease.WriteAt([]byte{1}, 0); err != nil || count != 1 {
		return ErrStorage
	}
	if s.lease.Sync() != nil || s.checkMarker(true) != nil || storeSecretRecord(s.item, record) != nil || s.checkMarker(true) != nil {
		return ErrStorage
	}
	// Only a completed, reaped successful helper permits clearing the fence.
	// Any failed/timed-out invocation leaves the marker for later openers to deny.
	if s.lease.Truncate(0) != nil || s.lease.Sync() != nil || s.check() != nil {
		return ErrStorage
	}
	s.version, s.credential = version, cloneCredential(credential)
	return nil
}

func (s *nativeSecretStorage) close() error {
	s.credential = nil
	s.item, s.directory = "", ""
	failed := false
	if s.lease != nil {
		failed = s.lease.Close() != nil
		s.lease = nil
	}
	for index := len(s.directories) - 1; index >= 0; index-- {
		if s.directories[index].file.Close() != nil {
			failed = true
		}
	}
	s.directories = nil
	if failed {
		return ErrStorage
	}
	return nil
}
