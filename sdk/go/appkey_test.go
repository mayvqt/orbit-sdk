package orbit

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
)

func testAppKey() AppKey {
	key, err := ParseAppKey("orbit_app_test_aHR0cHM6Ly9vcmJpdC5leGFtcGxlLnRlc3Q.app.test")
	if err != nil {
		panic(err)
	}
	return key
}

func TestSharedAppKeyVectors(t *testing.T) {
	data, err := os.ReadFile("../../contracts/sdk/app-keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		FormatVersion int `json:"format_version"`
		Cases         []struct {
			Name          string      `json:"name"`
			Key           string      `json:"key"`
			Valid         bool        `json:"valid"`
			APIOrigin     string      `json:"api_origin"`
			Issuer        string      `json:"issuer"`
			ApplicationID string      `json:"application_id"`
			EnvironmentID string      `json:"environment_id"`
			Environment   Environment `json:"environment"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.FormatVersion != 1 || len(corpus.Cases) != 27 {
		t.Fatalf("invalid shared app-key corpus: %v", err)
	}
	for _, fixture := range corpus.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			parsed, err := ParseAppKey(fixture.Key)
			if !fixture.Valid {
				if err == nil {
					t.Fatal("invalid app key was accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if parsed.APIOrigin() != fixture.APIOrigin || parsed.Issuer() != fixture.Issuer || parsed.ApplicationID() != fixture.ApplicationID || parsed.EnvironmentID() != fixture.EnvironmentID || parsed.Environment() != fixture.Environment {
				t.Fatalf("unexpected parsed key: %+v", parsed)
			}
		})
	}
}

type loadCountingStorage struct {
	MemoryStorage
	loads atomic.Int32
}

func (s *loadCountingStorage) Load() (uint64, *StoredCredential, error) {
	s.loads.Add(1)
	return s.MemoryStorage.Load()
}

func TestClientRejectsAppKeyTransportOriginMismatchBeforeStorageOrNetwork(t *testing.T) {
	var requests atomic.Int32
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		return testResponse(request, http.StatusOK, `{}`), nil
	})
	storage := &loadCountingStorage{}
	otherKey, err := ParseAppKey("orbit_app_test_aHR0cHM6Ly9vdGhlci5leGFtcGxlLnRlc3Q.app.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClientWithStorage(otherKey, Device{InstallationID: "installation_1234"}, transport, storage); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("mismatched app key and transport were accepted: %v", err)
	}
	if storage.loads.Load() != 0 || requests.Load() != 0 {
		t.Fatalf("mismatch reached storage or network: loads=%d requests=%d", storage.loads.Load(), requests.Load())
	}
	if _, err := NewClientWithStorage(testAppKey(), Device{InstallationID: "installation_1234"}, transport, storage); err != nil {
		t.Fatalf("matching app key and transport rejected: %v", err)
	}
}

func TestLoopbackAppKeyParsingIsExplicit(t *testing.T) {
	encode := func(origin string) string {
		return "orbit_app_test_" + base64.RawURLEncoding.EncodeToString([]byte(origin)) + ".app.test"
	}
	if _, err := ParseAppKey(encode("http://127.0.0.1:8080")); err == nil {
		t.Fatal("public parser accepted HTTP")
	}
	if _, err := parseAppKey(encode("http://127.0.0.1:8080"), "http", true); err != nil {
		t.Fatal(err)
	}
	if _, err := parseAppKey(encode("http://localhost:8080"), "http", true); err == nil {
		t.Fatal("local parser accepted a hostname instead of a loopback literal")
	}
}
