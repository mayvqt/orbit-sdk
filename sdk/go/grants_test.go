package orbit

import (
	"encoding/json"
	"os"
	"testing"
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
