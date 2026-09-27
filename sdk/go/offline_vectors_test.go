package orbit

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

type offlineVectorContext struct {
	AppKey       string  `json:"app_key"`
	Installation string  `json:"installation_id"`
	Fingerprint  *string `json:"fingerprint"`
	Provider     *string `json:"fingerprint_provider"`
	Now          int64   `json:"now"`
	Minimum      int64   `json:"minimum_sequence"`
}

func TestSharedOfflineFileVectors(t *testing.T) {
	data, err := os.ReadFile("../../contracts/sdk/offline-files.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Format   int                  `json:"format_version"`
		JWKS     json.RawMessage      `json:"jwks"`
		Expected offlineVectorContext `json:"expected"`
		Cases    []struct {
			Name     string          `json:"name"`
			Token    string          `json:"token"`
			Valid    bool            `json:"valid"`
			JWKS     json.RawMessage `json:"jwks"`
			Expected json.RawMessage `json:"expected"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Format != 1 || len(corpus.Cases) != 104 {
		t.Fatalf("offline vector corpus format/count: %d/%d", corpus.Format, len(corpus.Cases))
	}
	firstApp, err := ParseAppKey(corpus.Expected.AppKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := parseOfflineKeys(corpus.JWKS, firstApp.environment)
	if err != nil {
		t.Fatal(err)
	}
	first, err := verifyOfflineFile([]byte(corpus.Cases[0].Token), keys, firstApp, corpus.Expected.Installation, nil, nil, corpus.Expected.Now, corpus.Expected.Minimum)
	if err != nil {
		t.Fatal(err)
	}
	const expectedDigest = "8aed1c86dab86f56c744802ee68650041ddc12e8d56bb6d73c2f40049424740a"
	if first.ContentDigest != expectedDigest {
		t.Fatalf("canonical claims digest differs from shared Python/C# baseline: %s", first.ContentDigest)
	}
	// A reversed JSON field order retains the same canonical claims digest and
	// therefore remains a valid equal-sequence renewal of the same issuance.
	fixtureKey, _, err := offlineFixtureForVectors()
	if err != nil {
		t.Fatal(err)
	}
	reordered := reorderAndSignOfflineVector(t, corpus.Cases[0].Token, fixtureKey, false)
	reorderedClaims, err := verifyOfflineFile([]byte(reordered), keys, firstApp, corpus.Expected.Installation, nil, nil, corpus.Expected.Now, corpus.Expected.Minimum)
	if err != nil || reorderedClaims.ContentDigest != first.ContentDigest || reorderedClaims.IssuanceID != first.IssuanceID || reorderedClaims.Sequence != first.Sequence {
		t.Fatalf("reordered same-issuance claims mismatch: %+v, %v", reorderedClaims, err)
	}
	changed := reorderAndSignOfflineVector(t, corpus.Cases[0].Token, fixtureKey, true)
	changedClaims, err := verifyOfflineFile([]byte(changed), keys, firstApp, corpus.Expected.Installation, nil, nil, corpus.Expected.Now, corpus.Expected.Minimum)
	if err != nil || changedClaims.IssuanceID != first.IssuanceID || changedClaims.Sequence != first.Sequence || changedClaims.ContentDigest == first.ContentDigest {
		t.Fatalf("changed same-issuance claims did not produce a distinct digest: %+v, %v", changedClaims, err)
	}
	compactKeys, err := json.Marshal(corpus.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	exactKeys := append(append([]byte(nil), compactKeys...), []byte(strings.Repeat(" ", 16*1024-len(compactKeys)))...)
	if _, err := parseOfflineKeys(exactKeys, firstApp.environment); err != nil {
		t.Fatalf("exact-limit trusted key set rejected: %v", err)
	}
	if _, err := parseOfflineKeys(append(exactKeys, ' '), firstApp.environment); err == nil {
		t.Fatal("oversized trusted key set accepted")
	}
	if _, err := parseOfflineKeys([]byte(`{"keys":[],"keys":[]}`), firstApp.environment); err == nil {
		t.Fatal("duplicate raw JWKS field accepted")
	}
	exactFile := append([]byte(corpus.Cases[0].Token), []byte(strings.Repeat(" ", 16*1024-len(corpus.Cases[0].Token)))...)
	if _, err := verifyOfflineFile(exactFile, keys, firstApp, corpus.Expected.Installation, nil, nil, corpus.Expected.Now, corpus.Expected.Minimum); err != nil {
		t.Fatalf("exact-limit signed file rejected: %v", err)
	}
	if _, err := verifyOfflineFile(append(exactFile, ' '), keys, firstApp, corpus.Expected.Installation, nil, nil, corpus.Expected.Now, corpus.Expected.Minimum); err == nil {
		t.Fatal("oversized signed file accepted")
	}
	for _, vector := range corpus.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			expected := corpus.Expected
			if len(vector.Expected) > 0 {
				var overrides map[string]json.RawMessage
				if err := json.Unmarshal(vector.Expected, &overrides); err != nil {
					t.Fatal(err)
				}
				base, _ := json.Marshal(expected)
				var merged map[string]json.RawMessage
				_ = json.Unmarshal(base, &merged)
				for name, value := range overrides {
					merged[name] = value
				}
				base, _ = json.Marshal(merged)
				if err := json.Unmarshal(base, &expected); err != nil {
					t.Fatal(err)
				}
			}
			key, e := ParseAppKey(expected.AppKey)
			if e != nil {
				t.Fatal(e)
			}
			jwks := corpus.JWKS
			if len(vector.JWKS) > 0 {
				jwks = vector.JWKS
			}
			keys, e := parseOfflineKeys(jwks, key.environment)
			if e != nil {
				if vector.Valid {
					t.Fatal(e)
				}
				return
			}
			_, e = verifyOfflineFile([]byte(vector.Token), keys, key, expected.Installation, expected.Fingerprint, expected.Provider, expected.Now, expected.Minimum)
			if (e == nil) != vector.Valid {
				t.Fatalf("valid=%v error=%v", vector.Valid, e)
			}
		})
	}
}

func offlineFixtureForVectors() (*ecdsa.PrivateKey, []byte, error) {
	data, err := os.ReadFile("../rust/tests/fixtures/es256-test-private.pem")
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("missing signing fixture")
	}
	keyValue, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, ok := keyValue.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("fixture is not ES256")
	}
	return key, data, nil
}

func reorderAndSignOfflineVector(t *testing.T, token string, key *ecdsa.PrivateKey, change bool) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("bad shared fixture token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if change {
		claims["sub"] = json.RawMessage(`"changed-licence"`)
	}
	names := make([]string, 0, len(claims))
	for name := range claims {
		names = append(names, name)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	var builder strings.Builder
	builder.WriteByte('{')
	for i, name := range names {
		if i != 0 {
			builder.WriteByte(',')
		}
		quoted, _ := json.Marshal(name)
		builder.Write(quoted)
		builder.WriteByte(':')
		builder.Write(claims[name])
	}
	builder.WriteByte('}')
	message := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(builder.String()))
	digest := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}
