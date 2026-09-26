//go:build darwin && cgo

package orbit

/*
#include <stdlib.h>
#include "macos_native.h"
*/
import "C"

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

const installedDataName = "orbit-storage.bin"

type macDirectory struct {
	path string
	name string
	file *os.File
}

type macInstalledFiles struct {
	directory    string
	directories  []macDirectory
	lease        *os.File
	current      *os.File
	allowMissing bool
}

func openInstalledFiles(path string, _ []byte) (_ installedFiles, provider string, created bool, err error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return nil, "", false, ErrConfiguration
	}
	for _, component := range strings.Split(path, string(filepath.Separator)) {
		if component == ".." {
			return nil, "", false, ErrConfiguration
		}
	}
	clean := filepath.Clean(path)
	for _, component := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return nil, "", false, ErrConfiguration
		}
	}
	files := &macInstalledFiles{directory: clean}
	defer func() {
		if err != nil {
			_ = files.close()
		}
	}()
	var nativeErrno C.int
	root := C.orbit_open_root_directory(&nativeErrno)
	if root < 0 {
		return nil, "", false, ErrStorage
	}
	files.directories = append(files.directories, macDirectory{path: "/", file: os.NewFile(uintptr(root), "Orbit state root")})
	current := "/"
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	for index, name := range parts {
		parent := files.directories[len(files.directories)-1].file
		if !macFilesystemLocal(parent) {
			return nil, "", false, ErrStorage
		}
		component := C.CString(name)
		nativeErrno = 0
		fd := C.orbit_open_directory_at(C.int(parent.Fd()), component, &nativeErrno)
		wasCreated := false
		if fd < 0 && nativeErrno == C.ENOENT {
			nativeErrno = 0
			if C.orbit_make_directory_at(C.int(parent.Fd()), component, &nativeErrno) == 0 {
				wasCreated = true
			} else if nativeErrno != C.EEXIST {
				C.free(unsafe.Pointer(component))
				return nil, "", false, ErrStorage
			}
			fd = C.orbit_open_directory_at(C.int(parent.Fd()), component, &nativeErrno)
		}
		C.free(unsafe.Pointer(component))
		if fd < 0 {
			return nil, "", false, ErrStorage
		}
		current = filepath.Join(current, name)
		child := os.NewFile(uintptr(fd), "Orbit state directory")
		files.directories = append(files.directories, macDirectory{path: current, name: name, file: child})
		if !macDirectoryAllowed(child, index == len(parts)-1) || !macFilesystemLocal(child) {
			return nil, "", false, ErrStorage
		}
		if wasCreated && (macSyncDirectory(child) != nil || macSyncDirectory(parent) != nil) {
			return nil, "", false, ErrStorage
		}
	}
	if len(files.directories) < 2 {
		return nil, "", false, ErrConfiguration
	}
	leaf := files.leaf()
	lockName := C.CString(storageLockName)
	flags := C.int(C.ORBIT_OPEN_READ | C.ORBIT_OPEN_WRITE | C.ORBIT_OPEN_NONBLOCK)
	nativeErrno = 0
	leaseFD := C.orbit_open_file_at(C.int(leaf.Fd()), lockName, flags|C.ORBIT_OPEN_CREATE_EXCLUSIVE, 0600, &nativeErrno)
	created = leaseFD >= 0
	if leaseFD < 0 && nativeErrno == C.EEXIST {
		leaseFD = C.orbit_open_file_at(C.int(leaf.Fd()), lockName, flags, 0, &nativeErrno)
	}
	C.free(unsafe.Pointer(lockName))
	if leaseFD < 0 {
		return nil, "", false, ErrStorage
	}
	files.lease = os.NewFile(uintptr(leaseFD), "Orbit installation lease")
	if err = macLock(files.lease); err != nil {
		return nil, "", false, err
	}
	files.allowMissing = created
	if err = files.check(); err != nil {
		return nil, "", false, err
	}
	if created && (macFullSync(files.lease) != nil || macSyncDirectory(leaf) != nil) {
		return nil, "", false, ErrStorage
	}
	return files, "private_file", created, nil
}

func macString(value string) (*C.char, func()) {
	text := C.CString(value)
	return text, func() { C.free(unsafe.Pointer(text)) }
}

func macInfo(file *os.File) (C.struct_orbit_file_info, error) {
	var information C.struct_orbit_file_info
	var nativeErrno C.int
	if file == nil || C.orbit_stat_fd(C.int(file.Fd()), &information, &nativeErrno) != 0 {
		return information, ErrStorage
	}
	return information, nil
}

func macInfoAt(parent *os.File, name string) (C.struct_orbit_file_info, C.int, error) {
	var information C.struct_orbit_file_info
	var nativeErrno C.int
	text, release := macString(name)
	defer release()
	if C.orbit_stat_at(C.int(parent.Fd()), text, &information, &nativeErrno) != 0 {
		return information, nativeErrno, ErrStorage
	}
	return information, 0, nil
}

func macSame(a, b C.struct_orbit_file_info) bool {
	return a.device == b.device && a.inode == b.inode
}

func macPrivate(information C.struct_orbit_file_info) bool {
	return information.owner == C.uint32_t(os.Geteuid()) && information.mode&0077 == 0
}

func macRegular(information C.struct_orbit_file_info) bool {
	return information.kind == 2 && macPrivate(information) && information.links == 1 && information.mode&07000 == 0
}

func macDirectoryAllowed(file *os.File, leaf bool) bool {
	information, err := macInfo(file)
	if err != nil || information.kind != 1 || information.links == 0 {
		return false
	}
	return macDirectoryModeAllowed(uint32(information.owner), uint32(os.Geteuid()), uint32(information.mode), leaf)
}

func macFilesystemLocal(file *os.File) bool {
	var nativeErrno C.int
	return C.orbit_filesystem_is_local(C.int(file.Fd()), &nativeErrno) == 1
}

func macLock(file *os.File) error {
	var nativeErrno C.int
	if C.orbit_lock_exclusive_nonblocking(C.int(file.Fd()), &nativeErrno) == 0 {
		return nil
	}
	if C.orbit_is_would_block(nativeErrno) != 0 {
		return ErrInstallationInUse
	}
	return ErrStorage
}

func macSyncDirectory(file *os.File) error {
	var nativeErrno C.int
	if C.orbit_sync_directory(C.int(file.Fd()), &nativeErrno) != 0 {
		return ErrStorage
	}
	return nil
}

func macFullSync(file *os.File) error {
	var nativeErrno C.int
	if C.orbit_full_sync_file(C.int(file.Fd()), &nativeErrno) != 0 {
		return ErrStorage
	}
	return nil
}

func (s *macInstalledFiles) leaf() *os.File {
	return s.directories[len(s.directories)-1].file
}

func (s *macInstalledFiles) check() error {
	return s.checkWithMarker(false)
}

func (s *macInstalledFiles) checkWithMarker(pending bool) error {
	if s.lease == nil || len(s.directories) < 2 {
		return ErrStorage
	}
	for index, directory := range s.directories {
		held, err := macInfo(directory.file)
		if err != nil {
			return ErrStorage
		}
		actual := held
		if index > 0 {
			actual, _, err = macInfoAt(s.directories[index-1].file, directory.name)
			if err != nil {
				return ErrStorage
			}
		}
		if !macSame(held, actual) || actual.kind != 1 || !macDirectoryAllowed(directory.file, index == len(s.directories)-1) || !macFilesystemLocal(directory.file) {
			return ErrStorage
		}
	}
	leaf := s.leaf()
	held, err := macInfo(s.lease)
	if err != nil {
		return ErrStorage
	}
	actual, _, err := macInfoAt(leaf, storageLockName)
	if err != nil || !macSame(held, actual) || !macRegular(held) || !macRegular(actual) {
		return ErrStorage
	}
	if err := s.checkMarker(pending); err != nil {
		return err
	}
	data, missing, err := macInfoAt(leaf, installedDataName)
	if s.current == nil {
		if err == nil && macRegular(data) {
			return nil
		}
		if missing != C.ENOENT {
			return ErrStorage
		}
	} else {
		current, currentErr := macInfo(s.current)
		if err != nil || currentErr != nil || !macSame(current, data) || !macRegular(current) || !macRegular(data) {
			return ErrStorage
		}
	}
	return nil
}

func (s *macInstalledFiles) checkMarker(pending bool) error {
	var marker [2]byte
	count, err := s.lease.ReadAt(marker[:], 0)
	if err != nil && !errors.Is(err, io.EOF) || !pending && count != 0 || pending && (count != 1 || marker[0] != 1) {
		return ErrStorage
	}
	return nil
}

func (s *macInstalledFiles) writePendingMarker() error {
	count, err := s.lease.WriteAt([]byte{1}, 0)
	if err != nil || count != 1 || macFullSync(s.lease) != nil {
		return ErrStorage
	}
	return s.checkMarker(true)
}

func (s *macInstalledFiles) read() ([]byte, error) {
	if s.check() != nil {
		return nil, ErrStorage
	}
	text, release := macString(installedDataName)
	var nativeErrno C.int
	fd := C.orbit_open_file_at(C.int(s.leaf().Fd()), text, C.ORBIT_OPEN_READ|C.ORBIT_OPEN_NONBLOCK, 0, &nativeErrno)
	release()
	if fd < 0 {
		if nativeErrno == C.ENOENT {
			return nil, errStorageMissing
		}
		return nil, ErrStorage
	}
	file := os.NewFile(uintptr(fd), "Orbit installed state")
	information, err := macInfo(file)
	actual, _, pathErr := macInfoAt(s.leaf(), installedDataName)
	if err != nil || pathErr != nil || !macSame(information, actual) || !macRegular(information) || information.size == 0 || information.size > installedLimit {
		file.Close()
		return nil, ErrStorage
	}
	data, readErr := io.ReadAll(io.LimitReader(file, installedLimit+1))
	if readErr != nil || len(data) > installedLimit || s.check() != nil {
		clear(data)
		file.Close()
		return nil, ErrStorage
	}
	previous := s.current
	s.current = file
	if previous != nil {
		_ = previous.Close()
	}
	return data, nil
}

func (s *macInstalledFiles) write(data []byte) error {
	if s.check() != nil || len(data) == 0 || len(data) > installedLimit {
		return ErrStorage
	}
	old, err := s.read()
	clear(old)
	if err != nil && (!s.allowMissing || !errors.Is(err, errStorageMissing)) {
		return ErrStorage
	}
	if s.writePendingMarker() != nil || s.checkWithMarker(true) != nil {
		return ErrStorage
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return ErrStorage
	}
	temporaryName := ".orbit-" + hex.EncodeToString(entropy[:]) + ".tmp"
	text, release := macString(temporaryName)
	var nativeErrno C.int
	fd := C.orbit_open_file_at(C.int(s.leaf().Fd()), text, C.ORBIT_OPEN_READ|C.ORBIT_OPEN_WRITE|C.ORBIT_OPEN_CREATE_EXCLUSIVE, 0600, &nativeErrno)
	release()
	if fd < 0 {
		return ErrStorage
	}
	file := os.NewFile(uintptr(fd), "Orbit installed state temporary")
	cleanup := true
	defer func() {
		if cleanup {
			_ = file.Close()
			name, release := macString(temporaryName)
			var ignored C.int
			_ = C.orbit_unlink_at(C.int(s.leaf().Fd()), name, &ignored)
			release()
		}
	}()
	information, err := macInfo(file)
	actual, _, pathErr := macInfoAt(s.leaf(), temporaryName)
	if err != nil || pathErr != nil || !macSame(information, actual) || !macRegular(information) {
		return ErrStorage
	}
	if count, err := file.Write(data); err != nil || count != len(data) || macFullSync(file) != nil || s.checkWithMarker(true) != nil {
		return ErrStorage
	}
	oldCurrent := s.current
	oldName, releaseOld := macString(temporaryName)
	newName, releaseNew := macString(installedDataName)
	nativeErrno = 0
	if C.orbit_rename_at(C.int(s.leaf().Fd()), oldName, C.int(s.leaf().Fd()), newName, &nativeErrno) != 0 || macSyncDirectory(s.leaf()) != nil {
		releaseOld()
		releaseNew()
		return ErrStorage
	}
	releaseOld()
	releaseNew()
	s.current = file
	if oldCurrent != nil {
		_ = oldCurrent.Close()
	}
	cleanup = false
	if s.checkWithMarker(true) != nil {
		return ErrStorage
	}
	var truncateErrno C.int
	var completionErr error
	if C.orbit_truncate_file(C.int(s.lease.Fd()), &truncateErrno) != 0 || macFullSync(s.lease) != nil {
		completionErr = ErrStorage
	} else if s.check() != nil {
		completionErr = ErrStorage
	}
	if completionErr != nil {
		_ = s.writePendingMarker()
		return ErrStorage
	}
	s.allowMissing = false
	return nil
}

func (s *macInstalledFiles) close() error {
	var failed bool
	if s.current != nil && s.current.Close() != nil {
		failed = true
	}
	if s.lease != nil && s.lease.Close() != nil {
		failed = true
	}
	for index := len(s.directories) - 1; index >= 0; index-- {
		if s.directories[index].file.Close() != nil {
			failed = true
		}
	}
	s.current, s.lease, s.directories = nil, nil, nil
	if failed {
		return ErrStorage
	}
	return nil
}
