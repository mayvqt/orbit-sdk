//go:build windows

package orbit

import (
	"runtime"
	"syscall"
	"unsafe"
)

var installedAdvapi = syscall.NewLazyDLL("advapi32.dll")
var installedOpenThreadToken = installedAdvapi.NewProc("OpenThreadToken")

func rejectInstalledImpersonation() error {
	var token syscall.Token
	ok, _, err := installedOpenThreadToken.Call(^uintptr(1), syscall.TOKEN_QUERY, 1, uintptr(unsafe.Pointer(&token)))
	if ok != 0 {
		token.Close()
		return ErrStorage
	}
	if err != syscall.Errno(1008) {
		return ErrStorage
	}
	return nil
}

var installedConvertSD = installedAdvapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
var installedGetSecurity = installedAdvapi.NewProc("GetSecurityInfo")
var installedGetControl = installedAdvapi.NewProc("GetSecurityDescriptorControl")
var installedGetAce = installedAdvapi.NewProc("GetAce")
var installedGetAclInfo = installedAdvapi.NewProc("GetAclInformation")
var installedEqualSID = installedAdvapi.NewProc("EqualSid")
var installedCreateDirectory = storageKernel.NewProc("CreateDirectoryW")

type installedWindowsSecurity struct {
	descriptor     uintptr
	user           *syscall.SID
	system         *syscall.SID
	administrators *syscall.SID
}

func newInstalledWindowsSecurity() (*installedWindowsSecurity, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if rejectInstalledImpersonation() != nil {
		return nil, ErrStorage
	}
	var token syscall.Token
	process, err := syscall.GetCurrentProcess()
	if err != nil || syscall.OpenProcessToken(process, syscall.TOKEN_QUERY, &token) != nil {
		return nil, ErrStorage
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, ErrStorage
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return nil, ErrStorage
	}
	current, err := syscall.StringToSid(sid)
	if err != nil {
		return nil, ErrStorage
	}
	system, err := syscall.StringToSid("S-1-5-18")
	if err != nil {
		return nil, ErrStorage
	}
	admins, err := syscall.StringToSid("S-1-5-32-544")
	if err != nil {
		return nil, ErrStorage
	}
	sddl, err := syscall.UTF16PtrFromString("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return nil, ErrStorage
	}
	security := &installedWindowsSecurity{user: current, system: system, administrators: admins}
	ok, _, _ := installedConvertSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&security.descriptor)), 0)
	runtime.KeepAlive(sddl)
	if ok == 0 {
		return nil, ErrStorage
	}
	return security, nil
}
func (s *installedWindowsSecurity) attributes() *syscall.SecurityAttributes {
	return &syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: s.descriptor}
}
func (s *installedWindowsSecurity) close() {
	if s.descriptor != 0 {
		syscall.LocalFree(syscall.Handle(s.descriptor))
		s.descriptor = 0
	}
}
func sameInstalledSID(a, b *syscall.SID) bool {
	if a == nil || b == nil {
		return false
	}
	ok, _, _ := installedEqualSID.Call(uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(b)))
	runtime.KeepAlive(a)
	runtime.KeepAlive(b)
	return ok != 0
}
func (s *installedWindowsSecurity) check(handle syscall.Handle) error {
	if rejectInstalledImpersonation() != nil {
		return ErrStorage
	}
	var owner *syscall.SID
	var acl, descriptor uintptr
	result, _, _ := installedGetSecurity.Call(uintptr(handle), 1, 5, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&acl)), 0, uintptr(unsafe.Pointer(&descriptor)))
	if descriptor != 0 {
		defer syscall.LocalFree(syscall.Handle(descriptor))
	}
	if result != 0 || !sameInstalledSID(owner, s.user) || acl == 0 || descriptor == 0 {
		return ErrStorage
	}
	var control uint16
	var revision uint32
	ok, _, _ := installedGetControl.Call(descriptor, uintptr(unsafe.Pointer(&control)), uintptr(unsafe.Pointer(&revision)))
	if ok == 0 || control&0x1004 != 0x1004 {
		return ErrStorage
	} // Protected, present DACL.
	var info struct{ Count, Used, Free uint32 }
	ok, _, _ = installedGetAclInfo.Call(acl, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), 2)
	if ok == 0 || info.Count < 1 || info.Count > 3 || info.Used < 8 {
		return ErrStorage
	}
	userAllowed := false
	for i := uint32(0); i < info.Count; i++ {
		var ace uintptr
		ok, _, _ = installedGetAce.Call(acl, uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ok == 0 || ace < acl || ace > acl+uintptr(info.Used)-8 {
			return ErrStorage
		}
		header := (*struct {
			Kind, Flags uint8
			Size        uint16
			Mask        uint32
		})(unsafe.Pointer(ace))
		if header.Kind != 0 || header.Size < 20 || ace+uintptr(header.Size) > acl+uintptr(info.Used) || header.Flags&0x08 != 0 {
			return ErrStorage
		}
		sid := (*syscall.SID)(unsafe.Pointer(ace + 8))
		user := sameInstalledSID(sid, s.user)
		if !user && !sameInstalledSID(sid, s.system) && !sameInstalledSID(sid, s.administrators) {
			return ErrStorage
		}
		if user && header.Mask&0x1f01ff == 0x1f01ff {
			userAllowed = true
		}
	}
	if !userAllowed {
		return ErrStorage
	}
	return nil
}
func (s *installedWindowsSecurity) open(path string, access, share, creation, flags uint32) (syscall.Handle, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return syscall.InvalidHandle, ErrStorage
	}
	attributes := s.attributes()
	handle, err := syscall.CreateFile(name, access, share, attributes, creation, flags|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(s)
	return handle, err
}
func (s *installedWindowsSecurity) mkdir(path string) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return ErrStorage
	}
	attributes := s.attributes()
	ok, _, callErr := installedCreateDirectory.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(attributes)))
	runtime.KeepAlive(s)
	runtime.KeepAlive(name)
	runtime.KeepAlive(attributes)
	if ok == 0 && callErr != syscall.ERROR_ALREADY_EXISTS {
		return ErrStorage
	}
	return nil
}
