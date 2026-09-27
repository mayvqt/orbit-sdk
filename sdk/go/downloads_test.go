package orbit

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type downloadVectorCorpus struct {
	JWKS     json.RawMessage `json:"jwks"`
	Expected struct {
		AppKey   string `json:"app_key"`
		Endpoint string `json:"endpoint"`
		Now      int64  `json:"now"`
	} `json:"expected"`
	Cases []struct {
		Name     string          `json:"name"`
		Token    string          `json:"token"`
		Valid    bool            `json:"valid"`
		Expected json.RawMessage `json:"expected"`
		JWKS     json.RawMessage `json:"jwks"`
	} `json:"cases"`
}

func readDownloadCorpus(t *testing.T) downloadVectorCorpus {
	t.Helper()
	data, err := os.ReadFile("../../contracts/sdk/download-tickets.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus downloadVectorCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 110 {
		t.Fatalf("expected 110 ticket vectors, got %d", len(corpus.Cases))
	}
	return corpus
}

func TestSharedDownloadTicketVectors(t *testing.T) {
	corpus := readDownloadCorpus(t)
	for _, vector := range corpus.Cases {
		t.Run(vector.Name, func(t *testing.T) {
			appKey, endpoint, now := corpus.Expected.AppKey, corpus.Expected.Endpoint, corpus.Expected.Now
			if len(vector.Expected) != 0 {
				var override map[string]json.RawMessage
				if err := json.Unmarshal(vector.Expected, &override); err != nil {
					t.Fatal(err)
				}
				if raw := override["app_key"]; len(raw) != 0 {
					_ = json.Unmarshal(raw, &appKey)
				}
				if raw := override["endpoint"]; len(raw) != 0 {
					_ = json.Unmarshal(raw, &endpoint)
				}
				if raw := override["now"]; len(raw) != 0 {
					_ = json.Unmarshal(raw, &now)
				}
			}
			jwks := corpus.JWKS
			if len(vector.JWKS) != 0 {
				jwks = vector.JWKS
			}
			var verifier *DownloadTicketVerifier
			if err := json.Unmarshal(jwks, new(any)); err == nil {
				verifier, _ = NewDownloadTicketVerifier(appKey, endpoint, jwks)
			}
			valid := false
			if verifier != nil {
				ticket, err := verifier.Verify(vector.Token, time.Unix(now, 0).UTC())
				valid = err == nil
				if valid && vector.Name == "valid_maximum_term" && (ticket.LicenceID() != "licence" || ticket.ReleaseID() != "release_1" || ticket.ArtifactID() != "artifact_1" || ticket.SHA256() != "abababababababababababababababababababababababababababababababab" || ticket.ByteLength() != 1024 || ticket.TicketID() != "ticket_fixture_1" || !ticket.IssuedAt().Equal(time.Unix(corpus.Expected.Now, 0).UTC()) || !ticket.ExpiresAt().Equal(time.Unix(corpus.Expected.Now+120, 0).UTC())) {
					t.Fatal("verified metadata did not use native time and value types")
				}
			}
			if valid != vector.Valid {
				t.Fatalf("vector valid=%v, verifier accepted=%v", vector.Valid, valid)
			}
		})
	}
}

func TestDownloadVerifierCopiesKeysAndSupportsConcurrentVerification(t *testing.T) {
	corpus := readDownloadCorpus(t)
	keys := append(json.RawMessage(nil), corpus.JWKS...)
	verifier, err := NewDownloadTicketVerifier(corpus.Expected.AppKey, corpus.Expected.Endpoint, keys)
	if err != nil {
		t.Fatal(err)
	}
	for i := range keys {
		keys[i] = ' '
	}
	first := corpus.Cases[0]
	now := time.Unix(corpus.Expected.Now, 0)
	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ticket, e := verifier.Verify(first.Token, now); e != nil {
				errs <- e
			} else if ticket.ArtifactID() != "artifact_1" {
				errs <- ErrInvalidResponse
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestDownloadVerifierRejectsUnsafeEndpoints(t *testing.T) {
	corpus := readDownloadCorpus(t)
	endpointPrefix := "https://downloads.example.test/"
	exactLimit := endpointPrefix + strings.Repeat("a", 2048-len(endpointPrefix))
	if _, err := NewDownloadTicketVerifier(corpus.Expected.AppKey, exactLimit, corpus.JWKS); err != nil {
		t.Fatalf("rejected endpoint at the 2048 byte limit: %v", err)
	}
	for _, endpoint := range []string{
		"http://downloads.example.test/file", "https://user@downloads.example.test/file",
		"https://@downloads.example.test/file", "https:///downloads.example.test/file",
		"https://downloads.example.test:/file", "https://downloads.example.test:abc/file",
		"https://downloads.example.test:0/file", "https://downloads.example.test:65536/file",
		"https://%64ownloads.example.test/file",
		"https://:443/file", "https://[2001:db8::1/file",
		"https://downloads.example.test/file?", "https://downloads.example.test/file#part",
		"https://downloads.example.test/%zz", "https://downloads.example.test/a\\b",
		"https://downloads.example.test/has space", "https://downloads.example.test/" + strings.Repeat("a", 2049),
	} {
		if _, err := NewDownloadTicketVerifier(corpus.Expected.AppKey, endpoint, corpus.JWKS); err == nil {
			t.Fatalf("accepted unsafe endpoint %q", endpoint)
		}
	}
	for _, endpoint := range []string{
		"https://downloads.example.test:8443/file",
		"https://[2001:db8::1]:8443/file",
		"https://[::ffff:192.0.2.1]:8443/file",
	} {
		if _, err := NewDownloadTicketVerifier(corpus.Expected.AppKey, endpoint, corpus.JWKS); err != nil {
			t.Fatalf("rejected valid endpoint %q: %v", endpoint, err)
		}
	}
}

func TestDownloadVerifierErrorsNameTheRejectedInput(t *testing.T) {
	corpus := readDownloadCorpus(t)
	verifier, err := NewDownloadTicketVerifier(corpus.Expected.AppKey, corpus.Expected.Endpoint, corpus.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify("not-a-ticket"); !errors.Is(err, &Error{Kind: Denied, Code: "invalid_download_ticket"}) {
		t.Fatalf("invalid ticket: %v", err)
	}
	if _, err := NewDownloadTicketVerifier(corpus.Expected.AppKey, "http://downloads.example.test", corpus.JWKS); !errors.Is(err, &Error{Kind: Configuration, Code: "invalid_download_endpoint"}) {
		t.Fatalf("invalid endpoint: %v", err)
	}
	if _, err := NewDownloadTicketVerifier(corpus.Expected.AppKey, corpus.Expected.Endpoint, []byte(`{"keys":[]}`)); !errors.Is(err, &Error{Kind: Configuration, Code: "invalid_download_keys"}) || !errors.Is(err, ErrConfiguration) {
		t.Fatalf("invalid keys: %v", err)
	}
}
