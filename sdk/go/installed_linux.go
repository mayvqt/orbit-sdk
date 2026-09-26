//go:build linux

package orbit

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const installedDataName = "orbit-storage.bin"

type linuxInstalledFiles struct {
	lease        *nativeSecretStorage
	allowMissing bool
}

func openInstalledFiles(path string, _ []byte) (installedFiles, string, bool, error) {
	if err := createInstalledDirectory(path); err != nil {
		return nil, "", false, err
	}
	lease, created, err := openSecretStorageLease(path)
	if err != nil {
		return nil, "", false, err
	}
	files := &linuxInstalledFiles{lease: lease, allowMissing: created}
	if err := files.check(); err != nil {
		files.close()
		return nil, "", false, err
	}
	return files, "private_file", created, nil
}

// Walk from the root with pinned descriptors; mkdirat never follows a link.
// Existing permissions are validated, never silently repaired.
func createInstalledDirectory(path string) error {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) || filepath.Clean(path) == "/" {
		return ErrConfiguration
	}
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, err := syscall.Open("/", flags, 0)
	if err != nil {
		return ErrStorage
	}
	handles := []int{fd}
	defer func() {
		for i := len(handles) - 1; i >= 0; i-- {
			syscall.Close(handles[i])
		}
	}()
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	for i, part := range parts {
		next, err := syscall.Openat(fd, part, flags, 0)
		created := false
		if err == syscall.ENOENT {
			if err = syscall.Mkdirat(fd, part, 0700); err != nil && err != syscall.EEXIST {
				return ErrStorage
			}
			created = err == nil
			next, err = syscall.Openat(fd, part, flags, 0)
		}
		if err != nil {
			return ErrStorage
		}
		handles = append(handles, next)
		var stat syscall.Stat_t
		if syscall.Fstat(next, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFDIR || (created || i == len(parts)-1) && (stat.Uid != uint32(os.Geteuid()) || stat.Mode&077 != 0) {
			return ErrStorage
		}
		if !localInstalledFilesystem(next) {
			return ErrStorage
		}
		if created && (syscall.Fsync(next) != nil || syscall.Fsync(fd) != nil) {
			return ErrStorage
		}
		fd = next
	}
	return nil
}
func localInstalledFilesystem(fd int) bool {
	var stat syscall.Statfs_t
	if syscall.Fstatfs(fd, &stat) != nil {
		return false
	}
	switch uint32(stat.Type) {
	case 0xef53, 0x9123683e, 0x58465342, 0x01021994, 0x858458f6, 0x794c7630, 0x2fc12fc1, 0xf2f52010, 0x24051905, 0x3153464a, 0x52654973, 0x73717368:
		// ext, Btrfs, XFS, tmpfs, ramfs, overlay, ZFS, F2FS, UBIFS,
		// JFS, ReiserFS and read-only SquashFS ancestors.
		return true
	default:
		// Unknown providers may be network or userspace filesystems. Do not infer
		// exclusive local ownership from a pathname or silently select another store.
		return false
	}

}
func (s *linuxInstalledFiles) check() error {
	if s.lease == nil || s.lease.check() != nil {
		return ErrStorage
	}
	for _, d := range s.lease.directories {
		if !localInstalledFilesystem(int(d.file.Fd())) {
			return ErrStorage
		}
	}
	return nil
}
func (s *linuxInstalledFiles) dir() int {
	return int(s.lease.directories[len(s.lease.directories)-1].file.Fd())
}
func (s *linuxInstalledFiles) read() ([]byte, error) {
	if s.check() != nil {
		return nil, ErrStorage
	}
	fd, err := syscall.Openat(s.dir(), installedDataName, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err == syscall.ENOENT {
		return nil, errStorageMissing
	}
	if err != nil {
		return nil, ErrStorage
	}
	file := os.NewFile(uintptr(fd), "Orbit installed state")
	defer file.Close()
	if secretFileIdentity(file, filepath.Join(s.lease.directory, installedDataName), false, true) != nil {
		return nil, ErrStorage
	}
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || stat.Size <= 0 || stat.Size > installedLimit {
		return nil, ErrStorage
	}
	data, err := io.ReadAll(io.LimitReader(file, installedLimit+1))
	if err != nil || len(data) > installedLimit || s.check() != nil {
		clear(data)
		return nil, ErrStorage
	}
	return data, nil
}
func (s *linuxInstalledFiles) write(data []byte) error {
	if s.check() != nil || len(data) == 0 || len(data) > installedLimit {
		return ErrStorage
	}
	old, err := s.read()
	clear(old)
	if err != nil && (!s.allowMissing || !errors.Is(err, errStorageMissing)) {
		return ErrStorage
	}
	// Fence every replacement before touching data. A crash or failed write
	// must not reopen an older grant after an uncertain invalidation.
	if n, err := s.lease.lease.WriteAt([]byte{1}, 0); err != nil || n != 1 {
		return ErrStorage
	}
	if s.lease.lease.Sync() != nil || s.lease.checkMarker(true) != nil {
		return ErrStorage
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return ErrStorage
	}
	name := "orbit-storage." + hex.EncodeToString(entropy[:]) + ".tmp"
	fd, err := syscall.Openat(s.dir(), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return ErrStorage
	}
	file := os.NewFile(uintptr(fd), "Orbit installed state temporary")
	defer func() { file.Close(); syscall.Unlinkat(s.dir(), name) }()
	if secretFileIdentity(file, filepath.Join(s.lease.directory, name), false, true) != nil {
		return ErrStorage
	}
	if count, err := file.Write(data); err != nil || count != len(data) {
		return ErrStorage
	}
	if file.Sync() != nil || s.lease.checkMarker(true) != nil || syscall.Renameat(s.dir(), name, s.dir(), installedDataName) != nil || syscall.Fsync(s.dir()) != nil {
		return ErrStorage
	}
	if s.lease.lease.Truncate(0) != nil || s.lease.lease.Sync() != nil || s.check() != nil {
		return ErrStorage
	}
	s.allowMissing = false
	return nil
}
func (s *linuxInstalledFiles) close() error {
	if s.lease == nil {
		return nil
	}
	err := s.lease.close()
	s.lease = nil
	return err
}
