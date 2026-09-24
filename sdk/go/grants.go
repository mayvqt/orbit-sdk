package orbit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"math"
	"math/big"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type grantHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}
type grantClaims struct {
	Issuer              string          `json:"iss"`
	Audience            string          `json:"aud"`
	Subject             string          `json:"sub"`
	ID                  string          `json:"jti"`
	IssuedAt            int64           `json:"iat"`
	NotBefore           int64           `json:"nbf"`
	ExpiresAt           int64           `json:"exp"`
	ApplicationID       string          `json:"application_id"`
	EnvironmentID       string          `json:"environment_id"`
	ActivationID        string          `json:"activation_id"`
	InstallationID      string          `json:"installation_id"`
	BindingMode         string          `json:"binding_mode"`
	Fingerprint         *string         `json:"fingerprint"`
	FingerprintProvider *string         `json:"fingerprint_provider"`
	PolicyVersion       int32           `json:"policy_version"`
	Entitlements        map[string]bool `json:"entitlements"`
	RefreshAfter        int64           `json:"refresh_after"`
	OfflineAllowed      bool            `json:"offline_allowed"`
	LicenceExpiresAt    *int64          `json:"licence_expires_at"`
}
type jsonWebKey struct {
	KeyType   string `json:"kty"`
	Curve     string `json:"crv"`
	Algorithm string `json:"alg"`
	Purpose   string `json:"use"`
	KeyID     string `json:"kid"`
	X         string `json:"x"`
	Y         string `json:"y"`
}
type grantKeys map[string]*ecdsa.PublicKey

func canonicalBase64(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, ErrInvalidResponse
	}
	return decoded, nil
}
func onlyFields(data []byte, names ...string) error {
	v, err := uniqueJSON(data)
	if err != nil {
		return err
	}
	object, ok := v.(map[string]any)
	if !ok || len(object) != len(names) {
		return ErrInvalidResponse
	}
	for _, name := range names {
		if _, ok := object[name]; !ok {
			return ErrInvalidResponse
		}
	}
	return nil
}
func parseHeader(token string) (grantHeader, []byte, error) {
	var header grantHeader
	if len(token) > 16384 {
		return header, nil, ErrInvalidResponse
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return header, nil, ErrInvalidResponse
	}
	signature, err := canonicalBase64(parts[2])
	if err != nil || len(signature) != 64 {
		return header, nil, ErrInvalidResponse
	}
	headerBytes, err := canonicalBase64(parts[0])
	if err != nil {
		return header, nil, err
	}
	if onlyFields(headerBytes, "alg", "typ", "kid") != nil || decodeJSON(headerBytes, &header) != nil || header.Algorithm != "ES256" || header.Type != "orbit-access+jwt" || header.KeyID == "" || len(header.KeyID) > 128 {
		return header, nil, ErrInvalidResponse
	}
	claims, err := canonicalBase64(parts[1])
	if err != nil {
		return header, nil, err
	}
	return header, claims, nil
}
func parseKeys(data []byte) (grantKeys, error) {
	var set struct {
		Keys []jsonWebKey `json:"keys"`
	}
	if decodeJSON(data, &set) != nil || len(set.Keys) < 1 || len(set.Keys) > 8 {
		return nil, ErrInvalidResponse
	}
	// Reject untrusted JOSE key metadata, including URLs and private material.
	v, _ := uniqueJSON(data)
	entries := v.(map[string]any)["keys"].([]any)
	keys := make(grantKeys, len(set.Keys))
	for index, key := range set.Keys {
		fields := entries[index].(map[string]any)
		if len(fields) != 7 {
			return nil, ErrInvalidResponse
		}
		for _, name := range []string{"kty", "crv", "alg", "use", "kid", "x", "y"} {
			if _, ok := fields[name]; !ok {
				return nil, ErrInvalidResponse
			}
		}
		if key.KeyType != "EC" || key.Curve != "P-256" || key.Algorithm != "ES256" || key.Purpose != "sig" || key.KeyID == "" || len(key.KeyID) > 128 {
			return nil, ErrInvalidResponse
		}
		for _, c := range key.KeyID {
			if c > 127 {
				return nil, ErrInvalidResponse
			}
		}
		x, err := canonicalBase64(key.X)
		if err != nil || len(x) != 32 {
			return nil, ErrInvalidResponse
		}
		y, err := canonicalBase64(key.Y)
		if err != nil || len(y) != 32 {
			return nil, ErrInvalidResponse
		}
		public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !public.Curve.IsOnCurve(public.X, public.Y) {
			return nil, ErrInvalidResponse
		}
		if _, exists := keys[key.KeyID]; exists {
			return nil, ErrInvalidResponse
		}
		keys[key.KeyID] = public
	}
	return keys, nil
}

type expectedGrant struct {
	issuer, application, environment, licence, activation, installation string
	fingerprint, fingerprintProvider                                    *string
	credentialExpiresAt                                                 int64
	licenceExpiresAt                                                    *int64
	now                                                                 int64
}

func verifyGrant(token string, keys grantKeys, expected expectedGrant) (*grantClaims, error) {
	header, payload, err := parseHeader(token)
	if err != nil {
		return nil, err
	}
	key, known := keys[header.KeyID]
	if !known {
		return nil, ErrInvalidResponse
	}
	var claims grantClaims
	if err := decodeJSON(payload, &claims); err != nil {
		return nil, err
	}
	// The maintained JOSE implementation owns signature verification. Dates and
	// scope are evaluated below against the suspend-aware verified server clock.
	verified, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, func(parsed *jwt.Token) (any, error) {
		if parsed.Method != jwt.SigningMethodES256 {
			return nil, ErrInvalidResponse
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithoutClaimsValidation(), jwt.WithJSONNumber(), jwt.WithStrictDecoding())
	if err != nil || verified == nil || !verified.Valid {
		return nil, ErrInvalidResponse
	}
	bound := claims.BindingMode == "none" && claims.Fingerprint == nil && claims.FingerprintProvider == nil && expected.fingerprint == nil && expected.fingerprintProvider == nil
	if expected.fingerprint != nil && expected.fingerprintProvider != nil {
		bound = claims.BindingMode == "hwid" && equalString(claims.Fingerprint, expected.fingerprint) && equalString(claims.FingerprintProvider, expected.fingerprintProvider)
	}
	allowance := int64(300)
	if claims.OfflineAllowed {
		allowance = 86400
	}
	if claims.Issuer != expected.issuer || claims.Audience != "orbit:"+expected.application+":"+expected.environment || claims.Subject == "" || len(claims.Subject) > 128 || (expected.licence != "" && claims.Subject != expected.licence) || claims.ID == "" || len(claims.ID) > 128 || claims.ApplicationID != expected.application || claims.EnvironmentID != expected.environment || claims.ActivationID != expected.activation || claims.InstallationID != expected.installation || !bound || claims.PolicyVersion < 1 || claims.IssuedAt < 0 || claims.NotBefore != claims.IssuedAt || claims.IssuedAt > saturatingAdd(expected.now, 30) || claims.IssuedAt < saturatingAdd(expected.now, -30) || claims.ExpiresAt <= expected.now || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt > saturatingAdd(claims.IssuedAt, allowance) || claims.ExpiresAt > expected.credentialExpiresAt || !equalInt(claims.LicenceExpiresAt, expected.licenceExpiresAt) || (claims.LicenceExpiresAt != nil && claims.ExpiresAt > *claims.LicenceExpiresAt) || claims.RefreshAfter <= claims.IssuedAt || claims.RefreshAfter > claims.ExpiresAt || claims.RefreshAfter > saturatingAdd(claims.IssuedAt, 75) || (claims.RefreshAfter < saturatingAdd(claims.IssuedAt, 45) && claims.RefreshAfter != claims.ExpiresAt) || !validEntitlements(claims.Entitlements) {
		return nil, ErrInvalidResponse
	}
	return &claims, nil
}
func validEntitlements(features map[string]bool) bool {
	if features == nil || len(features) > 64 {
		return false
	}
	for name := range features {
		if len(name) < 1 || len(name) > 64 || name[0] < 'a' || name[0] > 'z' {
			return false
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				return false
			}
		}
	}
	return true
}
func equalInt(a, b *int64) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func saturatingAdd(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	if b < 0 && a < math.MinInt64-b {
		return math.MinInt64
	}
	return a + b
}
