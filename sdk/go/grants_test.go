package orbit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// Shared fixtures contain only fixed synthetic grants and public verification
// keys. The SDK implementation imports no backend code or signing material.
func TestSharedGrantVectors(t *testing.T) {
	path := os.Getenv("ORBIT_SDK_GRANT_VECTORS")
	if path == "" {
		path = "../../contracts/sdk/grants.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		FormatVersion int                        `json:"format_version"`
		JWKS          json.RawMessage            `json:"jwks"`
		Expected      map[string]json.RawMessage `json:"expected"`
		Cases         []struct {
			Name     string                     `json:"name"`
			Token    string                     `json:"token"`
			Valid    bool                       `json:"valid"`
			Expected map[string]json.RawMessage `json:"expected"`
			JWKS     json.RawMessage            `json:"jwks"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.FormatVersion != 1 {
		t.Fatalf("unsupported grant vector format: %d", corpus.FormatVersion)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("shared corpus is empty")
	}
	for _, vector := range corpus.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			fields := make(map[string]json.RawMessage, len(corpus.Expected))
			for name, value := range corpus.Expected {
				fields[name] = value
			}
			for name, value := range vector.Expected {
				fields[name] = value
			}
			encoded, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			var expected struct {
				Issuer              string  `json:"issuer"`
				Application         string  `json:"application"`
				Environment         string  `json:"environment"`
				Licence             string  `json:"licence"`
				Activation          string  `json:"activation"`
				Installation        string  `json:"installation"`
				Fingerprint         *string `json:"fingerprint"`
				FingerprintProvider *string `json:"fingerprint_provider"`
				CredentialExpiresAt *int64  `json:"credential_expires_at"`
				LicenceExpiresAt    *int64  `json:"licence_expires_at"`
				Now                 int64   `json:"now"`
			}
			if err := json.Unmarshal(encoded, &expected); err != nil {
				t.Fatal(err)
			}
			expiry := int64(0)
			if expected.CredentialExpiresAt != nil {
				expiry = *expected.CredentialExpiresAt
			}
			jwks := corpus.JWKS
			if vector.JWKS != nil {
				jwks = vector.JWKS
			}
			keys, err := parseKeys(jwks)
			if err == nil {
				_, err = verifyGrant(vector.Token, keys, expectedGrant{issuer: expected.Issuer, application: expected.Application, environment: expected.Environment, licence: expected.Licence, activation: expected.Activation, installation: expected.Installation, fingerprint: expected.Fingerprint, fingerprintProvider: expected.FingerprintProvider, credentialExpiresAt: expiry, credentialPersistent: expected.CredentialExpiresAt == nil, licenceExpiresAt: expected.LicenceExpiresAt, now: expected.Now})
			}
			if (err == nil) != vector.Valid {
				t.Fatalf("valid = %v, expected %v; error: %v", err == nil, vector.Valid, err)
			}
		})
	}
}

func TestRuntimeAllowsUnboundGrantWithRequestedMachineIdentity(t *testing.T) {
	data, err := os.ReadFile("../../contracts/sdk/grants.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		JWKS     json.RawMessage `json:"jwks"`
		Expected struct {
			Issuer              string `json:"issuer"`
			Application         string `json:"application"`
			Environment         string `json:"environment"`
			Licence             string `json:"licence"`
			Activation          string `json:"activation"`
			Installation        string `json:"installation"`
			Now                 int64  `json:"now"`
			CredentialExpiresAt int64  `json:"credential_expires_at"`
		} `json:"expected"`
		Cases []struct {
			Name  string `json:"name"`
			Token string `json:"token"`
			Valid bool   `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	keys, err := parseKeys(corpus.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	var token string
	for _, vector := range corpus.Cases {
		if vector.Name == "strict-valid" && vector.Valid {
			token = vector.Token
			break
		}
	}
	if token == "" {
		t.Fatal("strict-valid app fixture is missing")
	}
	fingerprint, provider := strings.Repeat("a", 64), "machine_v1"
	expected := expectedGrant{issuer: corpus.Expected.Issuer, application: corpus.Expected.Application, environment: corpus.Expected.Environment, licence: corpus.Expected.Licence, activation: corpus.Expected.Activation, installation: corpus.Expected.Installation, fingerprint: &fingerprint, fingerprintProvider: &provider, credentialExpiresAt: corpus.Expected.CredentialExpiresAt, now: corpus.Expected.Now}
	if _, err := verifyGrant(token, keys, expected); err == nil {
		t.Fatal("strict grant verification accepted unbound claims for a fingerprinted client")
	}
	expected.allowUnboundFingerprint = true
	claims, err := verifyGrant(token, keys, expected)
	if err != nil || claims.BindingMode != "none" || claims.Fingerprint != nil || claims.FingerprintProvider != nil {
		t.Fatalf("runtime grant validation rejected legitimate unbound claims: %#v, %v", claims, err)
	}
}

func TestUnboundGrantMustOmitFingerprintClaims(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const now int64 = 1800000000
	claims := jwt.MapClaims{
		"iss": "https://orbit.example.test", "aud": "orbit:app:test", "sub": "licence", "jti": "synthetic",
		"iat": now, "nbf": now, "exp": now + 300, "application_id": "app", "environment_id": "test",
		"activation_id": "activation", "installation_id": "installation", "binding_mode": "none",
		"fingerprint": nil, "fingerprint_provider": nil, "policy_version": 1,
		"entitlements": map[string]bool{"export": true}, "refresh_after": now + 60, "offline_allowed": false,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"], token.Header["kid"] = "orbit-access+jwt", "null-fingerprint"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, provider := strings.Repeat("a", 64), "machine_v1"
	expected := expectedGrant{
		issuer: "https://orbit.example.test", application: "app", environment: "test", licence: "licence",
		activation: "activation", installation: "installation", fingerprint: &fingerprint,
		fingerprintProvider: &provider, allowUnboundFingerprint: true,
		credentialExpiresAt: now + 3600, now: now,
	}
	if _, err := verifyGrant(signed, grantKeys{"null-fingerprint": &key.PublicKey}, expected); err == nil {
		t.Fatal("unbound grant with explicit null fingerprint claims was accepted")
	}
}
