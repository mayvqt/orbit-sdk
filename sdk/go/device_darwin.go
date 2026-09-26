//go:build darwin && cgo

package orbit

/*
#include <stdlib.h>
#include "macos_native.h"
*/
import "C"

func NativeFingerprint(applicationID, environmentID string) (string, error) {
	if !opaque(applicationID) || !opaque(environmentID) {
		return "", ErrConfiguration
	}
	var value [257]C.char
	var sourceLength C.size_t
	if C.orbit_platform_uuid(&value[0], C.size_t(len(value)), &sourceLength) != 0 {
		return "", &Error{Kind: Denied, Code: "device_identity_unavailable"}
	}
	identity, valid := normalizeMacOSPlatformUUID(C.GoStringN(&value[0], C.int(sourceLength)), int(sourceLength))
	if !valid {
		return "", &Error{Kind: Denied, Code: "device_identity_unavailable"}
	}
	return MachineFingerprint(applicationID, environmentID, "macos", identity)
}
