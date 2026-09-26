package orbit

import (
	"encoding/json"
	"os"
	"sync"
	"testing"
)

type sessionVectorCorpus struct {
	JWKS     json.RawMessage `json:"jwks"`
	Expected json.RawMessage `json:"expected"`
	Cases    []struct {
		Name     string          `json:"name"`
		Token    string          `json:"token"`
		Valid    bool            `json:"valid"`
		Expected json.RawMessage `json:"expected"`
		JWKS     json.RawMessage `json:"jwks"`
	} `json:"cases"`
}

func readSessionCorpus(t *testing.T) sessionVectorCorpus {
	t.Helper()
	data, err := os.ReadFile("../../contracts/sdk/session-grants.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus sessionVectorCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 184 {
		t.Fatalf("expected 184 session vectors, got %d", len(corpus.Cases))
	}
	return corpus
}

func sessionExpectedFromJSON(t *testing.T, raw json.RawMessage) (sessionExpected, Environment) {
	t.Helper()
	value, err := uniqueJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	fields := value.(map[string]any)
	stringField := func(name string) string {
		v, ok := fields[name].(string)
		if !ok {
			t.Fatalf("expected string %s", name)
		}
		return v
	}
	optionalString := func(name string) *string {
		v, ok := fields[name]
		if !ok || v == nil {
			return nil
		}
		text, ok := v.(string)
		if !ok {
			t.Fatalf("expected optional string %s", name)
		}
		return &text
	}
	optionalInt := func(name string) *int64 {
		v, ok := fields[name]
		if !ok || v == nil {
			return nil
		}
		n, ok := v.(json.Number)
		if !ok {
			t.Fatalf("expected optional integer %s", name)
		}
		parsed, err := n.Int64()
		if err != nil {
			t.Fatalf("invalid expected integer %s", name)
		}
		return &parsed
	}
	intField := func(name string) int64 {
		v, ok := fields[name].(json.Number)
		if !ok {
			return -1
		}
		n, err := v.Int64()
		if err != nil {
			return -1
		}
		return n
	}
	allow, _ := fields["allow_unbound_fingerprint"].(bool)
	environment := Environment(stringField("key_environment"))
	expected := sessionExpected{
		issuer: stringField("issuer"), application: stringField("application"), environment: stringField("environment"),
		activation: stringField("activation"), installation: stringField("installation"),
		fingerprint: optionalString("fingerprint"), fingerprintProvider: optionalString("fingerprint_provider"),
		allowUnboundFingerprint: allow, credentialExpiresAt: optionalInt("credential_expires_at"),
		licenceExpiresAt: optionalInt("licence_expires_at"), now: intField("now"),
		sessionID: stringField("session_id"), sequence: intField("sequence"),
	}
	if licence := optionalString("licence"); licence != nil {
		expected.licence = *licence
	}
	return expected, environment
}

func TestSharedSessionGrantVectors(t *testing.T) {
	corpus := readSessionCorpus(t)
	for _, vector := range corpus.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			base, environment := sessionExpectedFromJSON(t, corpus.Expected)
			merged, err := uniqueJSON(corpus.Expected)
			if err != nil {
				t.Fatal(err)
			}
			fields := merged.(map[string]any)
			if len(vector.Expected) != 0 {
				overrideValue, err := uniqueJSON(vector.Expected)
				if err != nil {
					t.Fatal(err)
				}
				for name, value := range overrideValue.(map[string]any) {
					fields[name] = value
				}
			}
			expectedRaw, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			base, environment = sessionExpectedFromJSON(t, expectedRaw)
			jwks := corpus.JWKS
			if len(vector.JWKS) != 0 {
				jwks = vector.JWKS
			}
			keys, keyErr := parseSessionKeys(jwks, environment)
			valid := false
			if keyErr == nil {
				_, err := verifySessionGrant(vector.Token, keys, base)
				valid = err == nil
			}
			if valid != vector.Valid {
				t.Fatalf("vector valid=%v, verifier accepted=%v", vector.Valid, valid)
			}
		})
	}
}

func TestSessionVerifierKeysAreCopiedAndConcurrent(t *testing.T) {
	corpus := readSessionCorpus(t)
	expected, environment := sessionExpectedFromJSON(t, corpus.Expected)
	keysData := append(json.RawMessage(nil), corpus.JWKS...)
	keys, err := parseSessionKeys(keysData, environment)
	if err != nil {
		t.Fatal(err)
	}
	for i := range keysData {
		keysData[i] = ' '
	}
	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := verifySessionGrant(corpus.Cases[0].Token, keys, expected); e != nil {
				errs <- e
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
