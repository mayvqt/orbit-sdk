package orbit

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strings"
)

const (
	offlineMaxSequence = int64(9007199254740991)
	offlineMaxLifetime = int64(366 * 86400)
	offlineMaxFile     = 16 * 1024
)

// OfflineRequest is a public, serializable request for a signed offline file.
// It contains no licence key, session, credential or proof of ownership.
type OfflineRequest struct {
	Format              string  `json:"format"`
	Version             int     `json:"version"`
	AppKey              string  `json:"app_key"`
	InstallationID      string  `json:"installation_id"`
	Fingerprint         *string `json:"fingerprint"`
	FingerprintProvider *string `json:"fingerprint_provider"`
}

func publicAppKey(key AppKey) string {
	prefix := "orbit_app_test_"
	if key.environment == EnvironmentLive {
		prefix = "orbit_app_live_"
	}
	return fmt.Sprintf("%s%s.%s.%s", prefix, base64.RawURLEncoding.EncodeToString([]byte(key.apiOrigin)), key.applicationID, key.environmentID)
}

type offlineFileClaims struct {
	Issuer, Audience, LicenceID, IssuanceID                    string
	IssuedAt, NotBefore, ExpiresAt                             int64
	ApplicationID, EnvironmentID, ActivationID, InstallationID string
	Sequence                                                   int64
	BindingMode                                                string
	Fingerprint, FingerprintProvider                           *string
	PolicyVersion                                              int64
	Entitlements                                               map[string]bool
	LicenceExpiresAt                                           *int64
	ContentDigest                                              string
	KeyID                                                      string
}

type offlineRuntime struct {
	claims        offlineFileClaims
	anchor        *timeAnchor
	uncertain     bool
	authorized    bool
	wallHighWater int64
	saved         offlineRecord
}

type offlineRecord struct {
	JWS           *string `json:"jws"`
	Sequence      int64   `json:"sequence"`
	IssuanceID    string  `json:"issuance_id"`
	ContentDigest string  `json:"content_digest"`
	VerifiedAt    int64   `json:"verified_at"`
	TimeHighWater int64   `json:"time_high_water"`
	WallHighWater int64   `json:"wall_high_water"`
}

func offlineError(code string) error { return &Error{Kind: Denied, Code: code} }

func parseOfflineKeys(data []byte, environment Environment) (grantKeys, error) {
	if len(data) == 0 || len(data) > 16*1024 {
		return nil, ErrConfiguration
	}
	if onlyFields(data, "keys") != nil {
		return nil, ErrConfiguration
	}
	keys, err := parseKeys(data)
	if err != nil {
		return nil, ErrConfiguration
	}
	prefix := "offline-test-"
	if environment == EnvironmentLive {
		prefix = "offline-live-"
	}
	for kid := range keys {
		if !strings.HasPrefix(kid, prefix) || len(kid) == len(prefix) {
			return nil, ErrConfiguration
		}
		for _, c := range kid {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return nil, ErrConfiguration
			}
		}
	}
	return keys, nil
}

func offlineString(obj map[string]any, name string) (string, bool) {
	v, ok := obj[name].(string)
	return v, ok
}
func offlineInt(obj map[string]any, name string) (int64, bool) {
	v, ok := obj[name].(json.Number)
	if !ok {
		return 0, false
	}
	n, err := v.Int64()
	return n, err == nil
}
func offlineOpaque(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func offlineFields(obj map[string]any, names ...string) bool {
	for _, n := range names {
		if _, ok := obj[n]; !ok {
			return false
		}
	}
	return true
}

func verifyOfflineFile(raw []byte, keys grantKeys, expected AppKey, installation string, fingerprint, provider *string, now, minimumSequence int64) (offlineFileClaims, error) {
	var result offlineFileClaims
	if len(raw) > offlineMaxFile {
		return result, ErrInvalidResponse
	}
	trimmed := strings.Trim(string(raw), " \t\r\n\v\f")
	if trimmed == "" {
		return result, ErrInvalidResponse
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return result, ErrInvalidResponse
	}
	hb, err := canonicalBase64(parts[0])
	if err != nil || onlyFields(hb, "alg", "typ", "kid") != nil {
		return result, ErrInvalidResponse
	}
	var header grantHeader
	if decodeJSON(hb, &header) != nil || header.Algorithm != "ES256" || header.Type != "orbit-offline+jwt" {
		return result, ErrInvalidResponse
	}
	key := keys[header.KeyID]
	if key == nil {
		return result, ErrInvalidResponse
	}
	envPrefix := "offline-test-"
	if expected.environment == EnvironmentLive {
		envPrefix = "offline-live-"
	}
	if !strings.HasPrefix(header.KeyID, envPrefix) || len(header.KeyID) == len(envPrefix) {
		return result, ErrInvalidResponse
	}
	pb, err := canonicalBase64(parts[1])
	if err != nil {
		return result, ErrInvalidResponse
	}
	sig, err := canonicalBase64(parts[2])
	if err != nil || len(sig) != 64 {
		return result, ErrInvalidResponse
	}
	objValue, err := uniqueJSON(pb)
	if err != nil {
		return result, ErrInvalidResponse
	}
	obj, ok := objValue.(map[string]any)
	if !ok {
		return result, ErrInvalidResponse
	}
	allowed := []string{"ver", "iss", "aud", "sub", "jti", "iat", "nbf", "exp", "application_id", "environment_id", "activation_id", "installation_id", "sequence", "binding_mode", "policy_version", "entitlements", "licence_expires_at", "fingerprint", "fingerprint_provider"}
	for name := range obj {
		found := false
		for _, candidate := range allowed {
			if name == candidate {
				found = true
				break
			}
		}
		if !found {
			return result, ErrInvalidResponse
		}
	}
	if !offlineFields(obj, "ver", "iss", "aud", "sub", "jti", "iat", "nbf", "exp", "application_id", "environment_id", "activation_id", "installation_id", "sequence", "binding_mode", "policy_version", "entitlements") {
		return result, ErrInvalidResponse
	}
	version, vok := offlineInt(obj, "ver")
	iss, iok := offlineString(obj, "iss")
	aud, aok := offlineString(obj, "aud")
	sub, sok := offlineString(obj, "sub")
	jti, jok := offlineString(obj, "jti")
	iat, iatok := offlineInt(obj, "iat")
	nbf, nbfok := offlineInt(obj, "nbf")
	exp, expok := offlineInt(obj, "exp")
	app, appok := offlineString(obj, "application_id")
	env, envok := offlineString(obj, "environment_id")
	activation, actok := offlineString(obj, "activation_id")
	install, instok := offlineString(obj, "installation_id")
	sequence, seqok := offlineInt(obj, "sequence")
	mode, modeok := offlineString(obj, "binding_mode")
	policy, policyok := offlineInt(obj, "policy_version")
	if !(vok && iok && aok && sok && jok && iatok && nbfok && expok && appok && envok && actok && instok && seqok && modeok && policyok) {
		return result, ErrInvalidResponse
	}
	if version != 1 || iss != expected.issuer || aud != "orbit-offline:"+expected.applicationID+":"+expected.environmentID || !offlineOpaque(sub, 1, 128) || !offlineOpaque(jti, 1, 128) || app != expected.applicationID || env != expected.environmentID || !offlineOpaque(activation, 1, 128) || install != installation || !offlineOpaque(install, 16, 128) || sequence < minimumSequence || sequence < 1 || sequence > offlineMaxSequence || policy < 1 || policy > math.MaxInt32 || iat < 0 || iat > 253402300799 || nbf != iat || exp <= iat || exp > 253402300799 || exp-iat > offlineMaxLifetime || iat > now+30 || exp <= now {
		return result, ErrInvalidResponse
	}
	var fp, fpProvider *string
	switch mode {
	case "none":
		if _, ok := obj["fingerprint"]; ok {
			return result, ErrInvalidResponse
		}
		if _, ok := obj["fingerprint_provider"]; ok {
			return result, ErrInvalidResponse
		}
	case "hwid":
		fv, fok := obj["fingerprint"].(string)
		pv, pok := obj["fingerprint_provider"].(string)
		if !fok || !pok || fingerprint == nil || provider == nil || fv != *fingerprint || pv != *provider {
			return result, ErrInvalidResponse
		}
		fp, fpProvider = &fv, &pv
	default:
		return result, ErrInvalidResponse
	}
	var licenceExpiry *int64
	if value, exists := obj["licence_expires_at"]; exists {
		n, ok := value.(json.Number)
		if !ok {
			return result, ErrInvalidResponse
		}
		v, e := n.Int64()
		if e != nil || v < exp || v > 253402300799 {
			return result, ErrInvalidResponse
		}
		licenceExpiry = &v
	}
	featuresRaw, ok := obj["entitlements"].(map[string]any)
	if !ok || len(featuresRaw) > 64 {
		return result, ErrInvalidResponse
	}
	features := make(map[string]bool, len(featuresRaw))
	for name, value := range featuresRaw {
		b, ok := value.(bool)
		if !ok || !validEntitlements(map[string]bool{name: b}) {
			return result, ErrInvalidResponse
		}
		features[name] = b
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return result, ErrInvalidResponse
	}
	canonicalClaims, err := json.Marshal(obj)
	if err != nil {
		return result, ErrInvalidResponse
	}
	digest := sha256.Sum256(canonicalClaims)
	result = offlineFileClaims{Issuer: iss, Audience: aud, LicenceID: sub, IssuanceID: jti, IssuedAt: iat, NotBefore: nbf, ExpiresAt: exp, ApplicationID: app, EnvironmentID: env, ActivationID: activation, InstallationID: install, Sequence: sequence, BindingMode: mode, Fingerprint: fp, FingerprintProvider: fpProvider, PolicyVersion: policy, Entitlements: features, LicenceExpiresAt: licenceExpiry, ContentDigest: fmtHex(digest[:]), KeyID: header.KeyID}
	return result, nil
}

func fmtHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = digits[v>>4]
		out[2*i+1] = digits[v&15]
	}
	return string(out)
}

func offlineAnchorNow(anchor *timeAnchor) (int64, int64, error) {
	if anchor == nil {
		return 0, 0, ErrClockUncertain
	}
	return anchor.nowWithWall()
}
