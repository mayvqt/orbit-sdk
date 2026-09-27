package orbit

import (
	"encoding/json"
	"runtime"
	"runtime/debug"
	"strings"
)

const (
	clientLanguage = "go"
	modulePath     = "github.com/mayvqt/orbit-sdk/sdk/go"
)

// clientHeader is this SDK's Orbit-Client header value.
var clientHeader = func() string {
	version := moduleVersion()
	platform := sanitizePlatform(goosName(runtime.GOOS) + "-" + goarchName(runtime.GOARCH))
	if header, ok := formatClientHeader(clientLanguage, version, platform); ok {
		return header
	}
	header, _ := formatClientHeader(clientLanguage, version, "unknown")
	return header
}()

// validAppVersion reports whether value follows the application-version grammar:
// N[.N[.N[.N]]][-PRE][+BUILD] in at most 32 bytes.
func validAppVersion(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	rest, build, hasBuild := strings.Cut(value, "+")
	core, pre, hasPre := strings.Cut(rest, "-")
	parts := strings.Split(core, ".")
	if len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if !versionNumber(part) {
			return false
		}
	}
	if hasPre {
		for _, part := range strings.Split(pre, ".") {
			if !versionIdentifier(part) || digits(part) && !versionNumber(part) {
				return false
			}
		}
	}
	if hasBuild {
		for _, part := range strings.Split(build, ".") {
			if !versionIdentifier(part) {
				return false
			}
		}
	}
	return true
}

func versionNumber(part string) bool {
	return digits(part) && (part == "0" || part[0] != '0')
}

func versionIdentifier(part string) bool {
	if part == "" {
		return false
	}
	for _, c := range []byte(part) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func formatClientHeader(language, version, platform string) (string, bool) {
	if len(language) < 1 || len(language) > 16 || language[0] < 'a' || language[0] > 'z' {
		return "", false
	}
	for _, c := range []byte(language) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return "", false
		}
	}
	if len(platform) < 1 || len(platform) > 32 || !(platform[0] >= 'a' && platform[0] <= 'z' || platform[0] >= '0' && platform[0] <= '9') {
		return "", false
	}
	for _, c := range []byte(platform) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return "", false
		}
	}
	header := language + "/" + version + " (" + platform + ")"
	if !validAppVersion(version) || len(header) > 128 {
		return "", false
	}
	return header, true
}

// moduleVersion reads this module's version from the build metadata. Source
// builds without a module version report 0.0.0.
func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "0.0.0"
	}
	version := ""
	if info.Main.Path == modulePath {
		version = info.Main.Version
	}
	for _, dependency := range info.Deps {
		if dependency.Path == modulePath {
			if dependency.Replace != nil {
				dependency = dependency.Replace
			}
			version = dependency.Version
		}
	}
	version = strings.TrimPrefix(version, "v")
	if validAppVersion(version) {
		return version
	}
	// Pseudo-versions can exceed the header grammar; keep their release core.
	if core, _, _ := strings.Cut(strings.SplitN(version, "+", 2)[0], "-"); validAppVersion(core) {
		return core
	}
	return "0.0.0"
}

func goosName(value string) string {
	if value == "darwin" {
		return "macos"
	}
	return value
}

func goarchName(value string) string {
	switch value {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "386":
		return "x86"
	}
	return value
}

func sanitizePlatform(value string) string {
	out := []byte(strings.ToLower(value))
	for i, c := range out {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			out[i] = '_'
		}
	}
	if len(out) > 32 {
		out = out[:32]
	}
	return string(out)
}

// updateHint returns the optional update_available version of an activation or
// validation reply. A present but malformed hint invalidates the reply.
func updateHint(data json.RawMessage) (string, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return "", ErrInvalidResponse
	}
	raw, present := fields["update_available"]
	if !present {
		return "", nil
	}
	var hint map[string]json.RawMessage
	var version string
	if json.Unmarshal(raw, &hint) != nil || hint == nil || hint["version"] == nil ||
		json.Unmarshal(hint["version"], &version) != nil || !validAppVersion(version) {
		return "", ErrInvalidResponse
	}
	return version, nil
}
