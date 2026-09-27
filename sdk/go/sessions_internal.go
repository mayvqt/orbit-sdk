package orbit

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"math"
	"math/big"
	"strings"
)

type sessionVerifierKeys struct{ keys grantKeys }

// parseSessionKeys is intentionally package-private: callers cannot select a
// JWT purpose through the public API.
func parseSessionKeys(data []byte, environment Environment) (sessionVerifierKeys, error) {
	if (environment != EnvironmentTest && environment != EnvironmentLive) || len(data) == 0 || len(data) > 16*1024 || onlyFields(data, "keys") != nil {
		return sessionVerifierKeys{}, ErrInvalidResponse
	}
	keys, err := parseKeys(append([]byte(nil), data...))
	if err != nil {
		return sessionVerifierKeys{}, ErrInvalidResponse
	}
	prefix := string(environment) + "-"
	for kid := range keys {
		if !opaque(kid) || !strings.HasPrefix(kid, prefix) || len(kid) == len(prefix) {
			return sessionVerifierKeys{}, ErrInvalidResponse
		}
	}
	return sessionVerifierKeys{keys: keys}, nil
}

type sessionExpected struct {
	issuer, application, environment      string
	licence, activation, installation     string
	fingerprint, fingerprintProvider      *string
	allowUnboundFingerprint               bool
	credentialExpiresAt, licenceExpiresAt *int64
	now                                   int64
	sessionID                             string
	sequence                              int64
}

type sessionGrant struct {
	SessionID, LicenceID, ActivationID, InstallationID, TicketID string
	Sequence, IssuedAt, ExpiresAt, RefreshAfter                  int64
	PolicyVersion                                                int64
	LicenceExpiresAt                                             *int64
	Entitlements                                                 map[string]bool
}

func verifySessionGrant(token string, keys sessionVerifierKeys, expected sessionExpected) (sessionGrant, error) {
	var zero sessionGrant
	if len(token) == 0 || len(token) > 16*1024 || !isASCII(token) || expected.now < 0 || expected.now > downloadMaxTime || !opaque(expected.sessionID) || len(expected.sessionID) < 16 || expected.sequence < 1 || expected.sequence > 9007199254740991 {
		return zero, ErrInvalidResponse
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return zero, ErrInvalidResponse
	}
	hb, err := canonicalBase64(parts[0])
	if err != nil || onlyFields(hb, "alg", "typ", "kid") != nil {
		return zero, ErrInvalidResponse
	}
	var header downloadHeader
	if decodeJSON(hb, &header) != nil || header.Algorithm != "ES256" || header.Type != "orbit-session+jwt" || !opaque(header.KeyID) {
		return zero, ErrInvalidResponse
	}
	key := keys.keys[header.KeyID]
	if key == nil {
		return zero, ErrInvalidResponse
	}
	payload, err := canonicalBase64(parts[1])
	if err != nil {
		return zero, ErrInvalidResponse
	}
	value, err := uniqueJSON(payload)
	if err != nil {
		return zero, ErrInvalidResponse
	}
	claims, ok := value.(map[string]any)
	if !ok {
		return zero, ErrInvalidResponse
	}
	known := []string{"iss", "aud", "sub", "jti", "iat", "nbf", "exp", "application_id", "environment_id", "activation_id", "installation_id", "binding_mode", "fingerprint", "fingerprint_provider", "policy_version", "entitlements", "refresh_after", "offline_allowed", "licence_expires_at", "session_id", "session_sequence"}
	for field := range claims {
		for _, exact := range known {
			if field != exact && strings.EqualFold(field, exact) {
				return zero, ErrInvalidResponse
			}
		}
	}
	for _, required := range []string{"iss", "aud", "sub", "jti", "iat", "nbf", "exp", "application_id", "environment_id", "activation_id", "installation_id", "binding_mode", "policy_version", "entitlements", "refresh_after", "offline_allowed", "session_id", "session_sequence"} {
		if _, present := claims[required]; !present {
			return zero, ErrInvalidResponse
		}
	}
	getText := func(name string, min, max int) (string, bool) {
		value, ok := claims[name].(string)
		return value, ok && len(value) >= min && len(value) <= max && asciiToken(value)
	}
	integer := func(name string, min, max int64) (int64, bool) {
		value, ok := claims[name].(json.Number)
		if !ok {
			return 0, false
		}
		n, err := value.Int64()
		return n, err == nil && n >= min && n <= max
	}
	issuer, iok := claims["iss"].(string)
	audience, aok := claims["aud"].(string)
	subject, sok := getText("sub", 1, 128)
	ticketID, jok := getText("jti", 1, 128)
	application, appok := getText("application_id", 1, 128)
	environment, envok := getText("environment_id", 1, 128)
	activation, activationOK := getText("activation_id", 1, 128)
	installation, installationOK := getText("installation_id", 1, 128)
	mode, modeOK := claims["binding_mode"].(string)
	sessionID, sessionOK := getText("session_id", 16, 128)
	sequence, sequenceOK := integer("session_sequence", 1, 9007199254740991)
	issued, issuedOK := integer("iat", 0, downloadMaxTime)
	notBefore, notBeforeOK := integer("nbf", 0, downloadMaxTime)
	expires, expiresOK := integer("exp", 0, downloadMaxTime)
	refresh, refreshOK := integer("refresh_after", 0, downloadMaxTime)
	policy, policyOK := integer("policy_version", 1, math.MaxInt32)
	offline, offlineOK := claims["offline_allowed"].(bool)
	if !(iok && aok && sok && jok && appok && envok && activationOK && installationOK && modeOK && sessionOK && sequenceOK && issuedOK && notBeforeOK && expiresOK && refreshOK && policyOK && offlineOK) || offline {
		return zero, ErrInvalidResponse
	}
	entitlementValues, ok := claims["entitlements"].(map[string]any)
	if !ok || len(entitlementValues) > 64 {
		return zero, ErrInvalidResponse
	}
	entitlements := make(map[string]bool, len(entitlementValues))
	for name, raw := range entitlementValues {
		enabled, ok := raw.(bool)
		if !ok {
			return zero, ErrInvalidResponse
		}
		entitlements[name] = enabled
	}
	if !validEntitlements(entitlements) {
		return zero, ErrInvalidResponse
	}
	var fingerprint, fingerprintProvider *string
	if raw, present := claims["fingerprint"]; present {
		value, ok := raw.(string)
		if !ok {
			return zero, ErrInvalidResponse
		}
		fingerprint = &value
	}
	if raw, present := claims["fingerprint_provider"]; present {
		value, ok := raw.(string)
		if !ok {
			return zero, ErrInvalidResponse
		}
		fingerprintProvider = &value
	}
	var licenceExpiry *int64
	if raw, present := claims["licence_expires_at"]; present && raw != nil {
		value, ok := raw.(json.Number)
		if !ok {
			return zero, ErrInvalidResponse
		}
		parsed, err := value.Int64()
		if err != nil || parsed < 0 || parsed > downloadMaxTime {
			return zero, ErrInvalidResponse
		}
		licenceExpiry = &parsed
	}
	bound := false
	switch mode {
	case "none":
		_, hasFingerprint := claims["fingerprint"]
		_, hasProvider := claims["fingerprint_provider"]
		bound = !hasFingerprint && !hasProvider &&
			(expected.fingerprint == nil && expected.fingerprintProvider == nil || expected.allowUnboundFingerprint && expected.fingerprint != nil && expected.fingerprintProvider != nil)
	case "hwid":
		bound = expected.fingerprint != nil && expected.fingerprintProvider != nil &&
			lowerHex(valueOrEmpty(fingerprint), 64) && validProvider(valueOrEmpty(fingerprintProvider)) &&
			equalString(fingerprint, expected.fingerprint) && equalString(fingerprintProvider, expected.fingerprintProvider)
	}
	var expectedLicence *string
	if expected.licence != "" {
		expectedLicence = &expected.licence
	}
	if issuer != expected.issuer || audience != "orbit-session:"+expected.application+":"+expected.environment || (expectedLicence != nil && subject != *expectedLicence) || application != expected.application || environment != expected.environment || activation != expected.activation || installation != expected.installation || sessionID != expected.sessionID || sequence != expected.sequence || !bound || issued > expected.now+30 || notBefore != issued || expires <= expected.now || expires <= issued || expires-issued > 120 || expected.credentialExpiresAt != nil && expires > *expected.credentialExpiresAt || !equalInt(licenceExpiry, expected.licenceExpiresAt) || licenceExpiry != nil && expires > *licenceExpiry || refresh <= issued || refresh > expires || refresh > issued+75 || refresh < issued+45 && refresh != expires {
		return zero, ErrInvalidResponse
	}
	input := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(input))
	sig, err := canonicalBase64(parts[2])
	if err != nil || len(sig) != 64 || !ecdsa.Verify(key, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return zero, ErrInvalidResponse
	}
	return sessionGrant{SessionID: sessionID, LicenceID: subject, ActivationID: activation, InstallationID: installation, TicketID: ticketID, Sequence: sequence, IssuedAt: issued, ExpiresAt: expires, RefreshAfter: refresh, PolicyVersion: policy, LicenceExpiresAt: licenceExpiry, Entitlements: entitlements}, nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
