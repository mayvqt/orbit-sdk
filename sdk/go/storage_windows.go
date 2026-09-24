//go:build windows

package orbit

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const storageDataName = "orbit-storage.bin"

var storageKernel = syscall.NewLazyDLL("kernel32.dll")
var storageDriveType = storageKernel.NewProc("GetDriveTypeW")
var storageSetFileInfo = storageKernel.NewProc("SetFileInformationByHandle")
var storageFinalPath = storageKernel.NewProc("GetFinalPathNameByHandleW")

type nativeWindowsStorage struct {
	directory    string
	directories  []syscall.Handle
	lease        syscall.Handle
	allowMissing bool
}

// OpenWindowsStorage opens an existing dedicated absolute local directory in
// the caller's private Windows profile. It never resets existing/corrupt state.
// The lifetime lease must be closed before another process/object opens it.
func OpenWindowsStorage(directory string, config Config, device Device) (*WindowsStorage, error) {
	scope, err := newStorageScope(config, device)
	if err != nil {
		return nil, err
	}
	files, err := openWindowsStorageFiles(directory)
	if err != nil {
		return nil, err
	}
	_, _, err = files.read(scope)
	if err == errStorageMissing && files.allowMissing {
		err = files.write(scope, 0, nil)
	}
	if err != nil {
		_ = files.close()
		return nil, ErrStorage
	}
	files.allowMissing = false
	return &WindowsStorage{state: &protectedStorageState{files: files, scope: scope}}, nil
}

func openWindowsStorageFiles(directory string) (_ *nativeWindowsStorage, err error) {
	directory = filepath.Clean(filepath.FromSlash(directory))
	volume := filepath.VolumeName(directory)
	if !filepath.IsAbs(directory) || len(volume) != 2 || volume[1] != ':' || len(directory) <= 3 || strings.Contains(directory[2:], ":") || strings.ContainsRune(directory, 0) {
		return nil, ErrConfiguration
	}
	for _, part := range strings.Split(directory[3:], `\`) {
		if part == "" || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return nil, ErrConfiguration
		}
	}
	if !localStorageDrive(volume + `\`) {
		return nil, ErrStorage
	}
	files := &nativeWindowsStorage{directory: directory, lease: syscall.InvalidHandle}
	defer func() {
		if err != nil {
			_ = files.close()
		}
	}()
	current := volume + `\`
	paths := []string{current}
	for _, part := range strings.Split(directory[3:], `\`) {
		current = filepath.Join(current, part)
		paths = append(paths, current)
	}
	for _, path := range paths {
		// Holding every directory without delete sharing prevents ancestor rename
		// replacement. Reparse attributes are checked again for every operation.
		handle, openErr := openStorageHandle(path, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
			syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS)
		if openErr != nil {
			return nil, ErrStorage
		}
		files.directories = append(files.directories, handle)
		if _, checkErr := storageHandleInfo(handle, true); checkErr != nil {
			return nil, ErrStorage
		}
	}
	lock := filepath.Join(directory, storageLockName)
	handle, openErr := openStorageHandle(lock, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, syscall.CREATE_NEW, 0)
	created := openErr == nil
	if openErr == syscall.ERROR_FILE_EXISTS || openErr == syscall.ERROR_ALREADY_EXISTS {
		handle, openErr = openStorageHandle(lock, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, syscall.OPEN_EXISTING, 0)
	}
	if openErr != nil {
		return nil, ErrStorage
	}
	files.lease = handle
	info, checkErr := storageHandleInfo(handle, false)
	if checkErr != nil || info.FileSizeHigh != 0 || info.FileSizeLow != 0 || files.checkDirectories() != nil {
		return nil, ErrStorage
	}
	if created && syscall.FlushFileBuffers(handle) != nil {
		return nil, ErrStorage
	}
	files.allowMissing = created
	return files, nil
}

func localStorageDrive(root string) bool {
	if storageDriveType.Find() != nil {
		return false
	}
	value, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return false
	}
	kind, _, _ := storageDriveType.Call(uintptr(unsafe.Pointer(value)))
	runtime.KeepAlive(value)
	return kind == 2 || kind == 3 || kind == 6 // Removable, fixed or RAM; never a network drive.
}

func openStorageHandle(path string, access, share, creation, flags uint32) (syscall.Handle, error) {
	value, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return syscall.InvalidHandle, ErrStorage
	}
	return syscall.CreateFile(value, access, share, nil, creation,
		flags|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func storageHandleInfo(handle syscall.Handle, directory bool) (syscall.ByHandleFileInformation, error) {
	var info syscall.ByHandleFileInformation
	kind, err := syscall.GetFileType(handle)
	if err != nil || kind != syscall.FILE_TYPE_DISK || syscall.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || !directory && info.NumberOfLinks != 1 {
		return info, ErrStorage
	}
	return info, nil
}

func (s *nativeWindowsStorage) checkDirectories() error {
	for _, handle := range s.directories {
		if _, err := storageHandleInfo(handle, true); err != nil {
			return ErrStorage
		}
	}
	return nil
}

func (s *nativeWindowsStorage) ciphertext() ([]byte, error) {
	if s.checkDirectories() != nil {
		return nil, ErrStorage
	}
	handle, err := openStorageHandle(filepath.Join(s.directory, storageDataName), syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ, syscall.OPEN_EXISTING, 0)
	if err == syscall.ERROR_FILE_NOT_FOUND {
		return nil, errStorageMissing
	}
	if err != nil {
		return nil, ErrStorage
	}
	file := os.NewFile(uintptr(handle), "Orbit protected storage")
	defer file.Close()
	info, err := storageHandleInfo(handle, false)
	if err != nil || info.FileSizeHigh != 0 || info.FileSizeLow == 0 || info.FileSizeLow > storageCiphertextLimit {
		return nil, ErrStorage
	}
	data := make([]byte, int(info.FileSizeLow))
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, ErrStorage
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); n != 0 || err != io.EOF || file.Close() != nil {
		return nil, ErrStorage
	}
	return data, nil
}

func (s *nativeWindowsStorage) read(scope storageScope) (uint64, *StoredCredential, error) {
	ciphertext, err := s.ciphertext()
	if err != nil {
		return 0, nil, err
	}
	plaintext, err := unprotectUserData(ciphertext, scope.entropy[:])
	if err != nil {
		return 0, nil, ErrStorage
	}
	defer func() { clear(plaintext); runtime.KeepAlive(plaintext) }()
	return decodeStorageRecord(scope, plaintext)
}

func (s *nativeWindowsStorage) write(scope storageScope, version uint64, credential *StoredCredential) error {
	plaintext, err := encodeStorageRecord(scope, version, credential)
	if err != nil {
		return ErrStorage
	}
	defer func() { clear(plaintext); runtime.KeepAlive(plaintext) }()
	ciphertext, err := protectUserData(plaintext, scope.entropy[:])
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > storageCiphertextLimit {
		return ErrStorage
	}
	if s.checkDirectories() != nil {
		return ErrStorage
	}
	destination := filepath.Join(s.directory, storageDataName)
	old, err := openStorageHandle(destination, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, syscall.OPEN_EXISTING, 0)
	if err == nil {
		_, checkErr := storageHandleInfo(old, false)
		closeErr := syscall.CloseHandle(old)
		if checkErr != nil || closeErr != nil {
			return ErrStorage
		}
	} else if err != syscall.ERROR_FILE_NOT_FOUND || !s.allowMissing {
		return ErrStorage
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ErrStorage
	}
	temporary := filepath.Join(s.directory, "orbit-storage."+hex.EncodeToString(random[:])+".tmp")
	const deleteAccess = 0x00010000
	const writeThrough = 0x80000000
	handle, err := openStorageHandle(temporary, syscall.GENERIC_WRITE|deleteAccess, 0, syscall.CREATE_NEW, writeThrough)
	if err != nil {
		return ErrStorage
	}
	file := os.NewFile(uintptr(handle), "Orbit protected storage temporary")
	defer func() { _ = file.Close(); _ = os.Remove(temporary) }()
	if _, err := storageHandleInfo(handle, false); err != nil {
		return ErrStorage
	}
	if count, err := file.Write(ciphertext); err != nil || count != len(ciphertext) {
		return ErrStorage
	}
	if file.Sync() != nil || s.checkDirectories() != nil || replaceStorageFile(handle, s.directories[len(s.directories)-1]) != nil || file.Sync() != nil || file.Close() != nil {
		return ErrStorage
	}
	s.allowMissing = false
	return nil
}

// Natural HANDLE alignment supplies FILE_RENAME_INFO's platform-specific padding.
type storageRenameInfo struct {
	replace   uint32
	directory syscall.Handle
	nameBytes uint32
	name      [1]uint16
}

func replaceStorageFile(source, directory syscall.Handle) error {
	if storageSetFileInfo.Find() != nil {
		return ErrStorage
	}
	name, err := storageDestinationName(directory)
	if err != nil {
		return ErrStorage
	}
	offset := int(unsafe.Offsetof(storageRenameInfo{}.name))
	buffer := make([]byte, offset+len(name)*2)
	info := (*storageRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.replace = 1
	info.directory = 0
	info.nameBytes = uint32((len(name) - 1) * 2)
	for index, value := range name {
		binary.LittleEndian.PutUint16(buffer[offset+index*2:], value)
	}
	// FileRenameInfo = 3. The temporary file remains exclusively open, with
	// DELETE access, through replacement. The destination name comes from its
	// pinned directory handle; every ancestor stays pinned against replacement.
	// Windows requires the full target name with a null RootDirectory here.
	// No attacker-controlled source pathname is reopened.
	ok, _, _ := storageSetFileInfo.Call(uintptr(source), 3, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	runtime.KeepAlive(buffer)
	if ok == 0 {
		return ErrStorage
	}
	return nil
}

func storageDestinationName(directory syscall.Handle) ([]uint16, error) {
	if storageFinalPath.Find() != nil {
		return nil, ErrStorage
	}
	if _, err := storageHandleInfo(directory, true); err != nil {
		return nil, ErrStorage
	}
	const limit = 32768
	path := make([]uint16, limit)
	count, _, _ := storageFinalPath.Call(uintptr(directory), uintptr(unsafe.Pointer(&path[0])), limit, 0)
	runtime.KeepAlive(path)
	if count == 0 || count >= limit || path[count] != 0 || count < 7 ||
		path[0] != '\\' || path[1] != '\\' || path[2] != '?' || path[3] != '\\' ||
		path[5] != ':' || path[6] != '\\' {
		return nil, ErrStorage
	}
	for _, unit := range path[:count] {
		if unit == 0 {
			return nil, ErrStorage
		}
	}
	name, err := syscall.UTF16FromString(storageDataName)
	if err != nil {
		return nil, ErrStorage
	}
	path = path[:count]
	if path[len(path)-1] != '\\' {
		path = append(path, '\\')
	}
	if len(path)+len(name) > limit {
		return nil, ErrStorage
	}
	return append(path, name...), nil
}

func (s *nativeWindowsStorage) close() error {
	failed := false
	if s.lease != syscall.InvalidHandle {
		failed = syscall.CloseHandle(s.lease) != nil
		s.lease = syscall.InvalidHandle
	}
	for index := len(s.directories) - 1; index >= 0; index-- {
		if syscall.CloseHandle(s.directories[index]) != nil {
			failed = true
		}
	}
	s.directories = nil
	s.directory = ""
	if failed {
		return ErrStorage
	}
	return nil
}
