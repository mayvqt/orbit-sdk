//go:build windows

package orbit

import (
	"runtime"
	"syscall"
	"unsafe"
)

const maxUserPlaintext = 32768
const maxUserCiphertext = 65536
const maxUserEntropy = 1024

// Go's syscall package registers crypt32.dll and kernel32.dll as system DLLs,
// loading them with LOAD_LIBRARY_SEARCH_SYSTEM32 rather than an app-path search.
var userProtectionDLL = syscall.NewLazyDLL("crypt32.dll")
var userProtectProc = userProtectionDLL.NewProc("CryptProtectData")
var userUnprotectProc = userProtectionDLL.NewProc("CryptUnprotectData")

// The pointer's natural alignment supplies DATA_BLOB's padding on Windows x64.
type userDataBlob struct {
	length uint32
	data   *byte
}

func protectUserData(plaintext, entropy []byte) ([]byte, error) {
	if len(plaintext) > maxUserPlaintext || len(entropy) == 0 || len(entropy) > maxUserEntropy {
		return nil, ErrStorage
	}
	return transformUserData(userProtectProc, plaintext, entropy, maxUserCiphertext)
}

func unprotectUserData(ciphertext, entropy []byte) ([]byte, error) {
	if len(ciphertext) > maxUserCiphertext || len(entropy) == 0 || len(entropy) > maxUserEntropy {
		return nil, ErrStorage
	}
	return transformUserData(userUnprotectProc, ciphertext, entropy, maxUserPlaintext)
}

func transformUserData(proc *syscall.LazyProc, input, entropy []byte, outputLimit uint32) (result []byte, err error) {
	if proc.Find() != nil {
		return nil, ErrStorage
	}
	in := userDataBlob{length: uint32(len(input)), data: unsafe.SliceData(input)}
	extra := userDataBlob{length: uint32(len(entropy)), data: unsafe.SliceData(entropy)}
	var out userDataBlob
	defer func() {
		if out.data == nil {
			return
		}
		// Even rejected oversized output and partially allocated failure output
		// belong to Windows and must be erased before LocalFree.
		zeroNativeUserData(out.data, out.length)
		if _, freeErr := syscall.LocalFree(syscall.Handle(unsafe.Pointer(out.data))); freeErr != nil {
			clear(result)
			runtime.KeepAlive(result)
			result, err = nil, ErrStorage
		}
	}()
	const cryptProtectUIForbidden = 1
	// Null description, reserved and prompt arguments; CurrentUser is the
	// default. Never set CRYPTPROTECT_LOCAL_MACHINE or request a description.
	ok, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&in)), 0, uintptr(unsafe.Pointer(&extra)),
		0, 0, cryptProtectUIForbidden, uintptr(unsafe.Pointer(&out)),
	)
	runtime.KeepAlive(input)
	runtime.KeepAlive(entropy)
	if ok == 0 || out.length > outputLimit || out.length != 0 && out.data == nil {
		return nil, ErrStorage
	}
	result = make([]byte, int(out.length))
	copy(result, unsafe.Slice(out.data, int(out.length)))
	return result, nil
}

// Keep the native writes in a separate call before passing the same allocation
// to LocalFree. The loop touches foreign memory, not a dead Go scratch buffer;
// uintptr iteration also avoids narrowing an oversized DWORD length to int.
//
//go:noinline
func zeroNativeUserData(data *byte, length uint32) {
	for offset := uintptr(0); offset < uintptr(length); offset++ {
		*(*byte)(unsafe.Add(unsafe.Pointer(data), offset)) = 0
	}
	runtime.KeepAlive(data)
}
