package orbit

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMeteringUsesCurrentProofAndExactRetryIdentity(t *testing.T) {
	var bodies []string
	transport := testTransport(t, func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		var input map[string]any
		_ = json.Unmarshal(b, &input)
		if input["credential"] == nil || input["installation_id"] == nil {
			t.Fatal("missing proof")
		}
		if len(bodies) == 1 {
			return testResponse(r, 503, `{"error":{"code":"service_unavailable","message":"Unavailable","request_id":"request"}}`), nil
		}
		return testResponse(r, 200, fmt.Sprintf(`{"name":"exports","period":"lifetime","limit":10,"used":2,"remaining":8,"period_started_at":null,"resets_at":null,"idempotency_key":%q,"consumed_units":2}`, input["idempotency_key"])), nil
	})
	client := testClient(t, &MemoryStorage{}, transport)
	installTestContext(t, client, "old", true)
	result, err := client.Consume(context.Background(), "exports", 2)
	if err != nil || result.Used != 2 || !validOperationID(result.OperationID) || len(bodies) != 2 || bodies[0] != bodies[1] {
		t.Fatalf("result=%+v err=%v bodies=%d", result, err, len(bodies))
	}
}
func TestMeteringCapacityDenialsAreValidatedAndKeepOperationID(t *testing.T) {
	for _, corrupt := range []string{"", "name", "remaining", "id", "units", "status", "duplicate"} {
		t.Run(corrupt, func(t *testing.T) {
			transport := testTransport(t, func(r *http.Request) (*http.Response, error) {
				counter := map[string]any{"name": "exports", "period": "day", "limit": 10, "used": 10, "remaining": 0, "period_started_at": "2026-09-27T00:00:00Z", "resets_at": "2026-09-28T00:00:00Z"}
				failure := map[string]any{"code": "usage_limit_reached", "message": "Denied", "request_id": "request", "counter": counter, "idempotency_key": "job_1234567890123456", "requested_units": 1}
				status := 409
				switch corrupt {
				case "name":
					counter["name"] = "other"
				case "remaining":
					counter["remaining"] = 2
				case "id":
					failure["idempotency_key"] = "other_id"
				case "units":
					failure["requested_units"] = true
				case "status":
					status = 201
				}
				data, _ := json.Marshal(map[string]any{"error": failure})
				if corrupt == "duplicate" {
					data = []byte(strings.Replace(string(data), `"used":10`, `"used":10,"used":10`, 1))
				}
				return testResponse(r, status, string(data)), nil
			})
			client := testClient(t, &MemoryStorage{}, transport)
			installTestContext(t, client, "old", true)
			_, err := client.Consume(context.Background(), "exports", 1, "job_1234567890123456")
			var mutation *MutationError
			if !errors.As(err, &mutation) || mutation.OperationID != "job_1234567890123456" {
				t.Fatalf("missing operation identity: %v", err)
			}
			if corrupt == "" {
				if mutation.Uncertain || mutation.Usage == nil || mutation.Usage.Used != 10 {
					t.Fatal("safe denial absent")
				}
			} else if !mutation.Uncertain || mutation.Usage != nil || !errors.Is(err, ErrInvalidResponse) {
				t.Fatal("malformed denial trusted")
			}
		})
	}
}
func TestResourceReleasedReplayDoesNotBecomeNewAllocation(t *testing.T) {
	transport := testTransport(t, func(r *http.Request) (*http.Response, error) {
		return testResponse(r, 200, `{"name":"projects","limit":5,"used":1,"remaining":4,"allocation_id":"allocation_old","resource_id":"project_one","units":2,"state":"released","idempotency_key":"job_1234567890123456"}`), nil
	})
	client := testClient(t, &MemoryStorage{}, transport)
	installTestContext(t, client, "old", true)
	result, err := client.AcquireResource(context.Background(), "projects", "project_one", 2, "job_1234567890123456")
	if err != nil || result.State != "released" || result.Used != 1 {
		t.Fatalf("released replay: %+v %v", result, err)
	}
}
func TestOnlineServiceCancellationAndOfflineMode(t *testing.T) {
	transport := testTransport(t, func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })
	client := testClient(t, &MemoryStorage{}, transport)
	installTestContext(t, client, "old", true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Consume(ctx, "exports", 1, "job_1234567890123456")
	var failure *MutationError
	if !errors.As(err, &failure) || failure.OperationID != "job_1234567890123456" || !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancel: %v", err)
	}
}
func downloadFixtureAuthorization(url, mode string, payload []byte) DownloadAuthorization {
	hash := sha256.Sum256(payload)
	expiry := time.Now().Add(time.Minute)
	a := DownloadAuthorization{artifact: Artifact{ID: "artifact", ReleaseID: "release", Platform: "linux", Architecture: "x64", Filename: "update.bin", ByteLength: int64(len(payload)), SHA256: hex.EncodeToString(hash[:]), DeliveryMode: mode, URL: url}}
	if mode == "protected" {
		a.ticket = "synthetic.ticket.proof"
		a.expiresAt = &expiry
	}
	return a
}
func TestVerifiedTLSDownloadRedirectsAndAtomicFailures(t *testing.T) {
	payload := []byte("verified seller bytes")
	var mu sync.Mutex
	var headers []string
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		headers = append(headers, r.Header.Get("Authorization")+"|"+r.Header.Get("Cookie")+"|"+r.Header.Get("Accept-Encoding"))
		mu.Unlock()
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/file", 302)
		case "/loop":
			http.Redirect(w, r, "/loop", 302)
		case "/encoded":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(payload)
		case "/wrong":
			_, _ = w.Write([]byte(strings.Repeat("x", len(payload))))
		case "/oversize":
			_, _ = w.Write(append(payload, 'x'))
		case "/short":
			_, _ = w.Write(payload[:3])
		case "/http":
			http.Redirect(w, r, "http://localhost/file", 302)
		default:
			_, _ = w.Write(payload)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DisableCompression: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	destination := filepath.Join(t.TempDir(), "artifact")
	auth := downloadFixtureAuthorization(server.URL+"/start", "protected", payload)
	if err := auth.download(context.Background(), destination, 100, client); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(destination)
	if string(data) != string(payload) {
		t.Fatal("wrong bytes")
	}
	mu.Lock()
	got := append([]string(nil), headers...)
	mu.Unlock()
	if len(got) != 2 || got[0] != "Bearer synthetic.ticket.proof||identity" || got[1] != "||identity" {
		t.Fatalf("redirect credentials: %v", got)
	}
	if err := auth.download(context.Background(), destination, 100, client); err == nil {
		t.Fatal("overwrote existing destination")
	}
	for _, path := range []string{"/wrong", "/short", "/oversize", "/encoded", "/loop", "/http"} {
		t.Run(path, func(t *testing.T) {
			broken := downloadFixtureAuthorization(server.URL+path, "public", payload)
			if err := broken.download(context.Background(), destination, 100, client, DownloadOptions{ReplaceExisting: true}); err == nil {
				t.Fatal("invalid download succeeded")
			}
			current, _ := os.ReadFile(destination)
			if string(current) != string(payload) {
				t.Fatal("failure replaced destination")
			}
			entries, _ := os.ReadDir(filepath.Dir(destination))
			if len(entries) != 1 {
				t.Fatal("temporary file leaked")
			}
		})
	}
	if err := auth.Download(context.Background(), filepath.Join(t.TempDir(), "untrusted"), 100); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
}
func TestCancelledTLSDownloadRemovesStaging(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.(http.Flusher).Flush(); close(entered); <-release }))
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	destination := filepath.Join(t.TempDir(), "artifact")
	auth := downloadFixtureAuthorization(server.URL, "public", []byte("bytes"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- auth.download(ctx, destination, 100, client) }()
	<-entered
	cancel()
	close(release)
	if err := <-done; !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancelled transfer: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(destination))
	if len(entries) != 0 {
		t.Fatal("cancelled transfer left a file")
	}
}

func TestUpdatesAndAuthorizationValidateExactTargetAndMode(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			artifact := downloadFixtureAuthorization("https://downloads.example.test/file", "public", []byte("payload")).artifact
			transport := testTransport(t, func(r *http.Request) (*http.Response, error) {
				var input map[string]any
				_ = json.NewDecoder(r.Body).Decode(&input)
				if strings.HasSuffix(r.URL.Path, "/updates") {
					if input["channel"] != "stable" || input["platform"] != "linux" || input["architecture"] != "x64" || input["credential"] == nil {
						t.Fatal("incorrect discovery proof or target")
					}
					selected := artifact
					if bad {
						selected.Architecture = "arm64"
					}
					number := int64(2)
					now := time.Now().UTC().Truncate(time.Second)
					release := Release{ID: "release", Channel: "stable", Version: "1.2", Notes: "notes", ReleaseNumber: &number, State: "published", CreatedAt: now, PublishedAt: &now, Artifacts: []Artifact{selected}}
					data, _ := json.Marshal(map[string]any{"release": release, "artifact": selected})
					return testResponse(r, 200, string(data)), nil
				}
				data, _ := json.Marshal(map[string]any{"artifact": artifact, "ticket": nil, "expires_at": nil})
				return testResponse(r, 200, string(data)), nil
			})
			client := testClient(t, &MemoryStorage{}, transport)
			installTestContext(t, client, "old", true)
			update, err := client.CheckForUpdates(context.Background(), 1, UpdateOptions{Platform: "linux", Architecture: "x64"})
			if bad {
				if !errors.Is(err, ErrInvalidResponse) {
					t.Fatal("wrong target accepted")
				}
				return
			}
			if err != nil || update.Release.Version != "1.2" {
				t.Fatalf("typed update: %+v %v", update, err)
			}
			authorization, err := client.AuthorizeDownload(context.Background(), "release", "artifact")
			if err != nil || authorization.Artifact().ID != "artifact" {
				t.Fatal(err)
			}
		})
	}
}

func TestImpossibleMeteringOutcomesRemainUncertain(t *testing.T) {
	const id = "job_1234567890123456"
	for _, resource := range []bool{false, true} {
		for _, denied := range []bool{false, true} {
			transport := testTransport(t, func(r *http.Request) (*http.Response, error) {
				counter := map[string]any{"name": "exports", "limit": 10, "used": 0, "remaining": 10}
				if resource {
					counter["name"] = "projects"
				} else {
					counter["period"] = "lifetime"
					counter["period_started_at"] = nil
					counter["resets_at"] = nil
				}
				var body any = counter
				status := 200
				if denied {
					code := "usage_limit_reached"
					if resource {
						code = "resource_limit_reached"
					}
					body = map[string]any{"error": map[string]any{"code": code, "message": "Denied", "request_id": "request", "counter": counter, "idempotency_key": id, "requested_units": 2}}
					status = 409
				} else {
					counter["idempotency_key"] = id
					if resource {
						counter["allocation_id"] = "allocation"
						counter["resource_id"] = "project"
						counter["units"] = 2
						counter["state"] = "active"
					} else {
						counter["consumed_units"] = 2
					}
				}
				data, _ := json.Marshal(body)
				return testResponse(r, status, string(data)), nil
			})
			client := testClient(t, &MemoryStorage{}, transport)
			installTestContext(t, client, "old", true)
			var err error
			if resource {
				_, err = client.AcquireResource(context.Background(), "projects", "project", 2, id)
			} else {
				_, err = client.Consume(context.Background(), "exports", 2, id)
			}
			var mutation *MutationError
			if !errors.As(err, &mutation) || !mutation.Uncertain || mutation.OperationID != id ||
				!errors.Is(err, ErrInvalidResponse) || mutation.Usage != nil || mutation.Resources != nil {
				t.Fatalf("impossible outcome trusted: resource=%v denied=%v err=%v", resource, denied, err)
			}
		}
	}
}
