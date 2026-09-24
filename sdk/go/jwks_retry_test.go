package orbit

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func unavailableKeys(request *http.Request) *http.Response {
	response := testResponse(request, http.StatusServiceUnavailable,
		`{"error":{"code":"service_unavailable","message":"Unavailable","request_id":"request"}}`)
	// Exercise the existing bounded Retry-After path without sleeping in tests.
	response.Header.Set("Retry-After", "30")
	return response
}

func TestUnavailableKeysPreserveOnlyExistingCredential(t *testing.T) {
	for _, cold := range []bool{true, false} {
		name := "previous_offline_grant"
		if cold {
			name = "cold_start"
		}
		t.Run(name, func(t *testing.T) {
			body, _, jwks := signedGrantResponse(t, false)
			unavailable := true
			requests := 0
			transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
				requests++
				if request.URL.Path == jwksPath {
					if unavailable {
						return unavailableKeys(request), nil
					}
					return testResponse(request, http.StatusOK, jwks), nil
				}
				return testResponse(request, http.StatusOK, body), nil
			})
			client := testClient(t, &MemoryStorage{}, transport)
			installTestContext(t, client, "old", true)
			if cold {
				client = testClient(t, client.storage, transport)
			}
			version, previous, err := client.storage.Load()
			if err != nil {
				t.Fatal(err)
			}
			generation, err := client.generation()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Refresh(context.Background()); !errors.Is(err, ErrTransient) {
				t.Fatalf("unavailable keys: %v, want transient", err)
			}
			if cold && (client.state.nextRetry < 15 || client.state.nextRetry > 44 ||
				client.state.retryAt.Before(time.Now().Add(14*time.Second)) ||
				client.state.retryAt.After(time.Now().Add(45*time.Second))) {
				t.Fatal("anchorless transient retry was not paced within the 15–44 second jitter window")
			}
			state, err := client.Snapshot()
			if err != nil || state.Access != AccessRefreshRequired || state.OfflineAllowed ||
				len(state.Entitlements) != 0 || state.ExpiresAt != nil || state.RemainingOfflineSeconds != 0 {
				t.Fatalf("unverified reply retained authority: %+v, %v", state, err)
			}
			requestsAfterFailure := requests
			for range 3 {
				if _, err := client.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrDenied) {
					t.Fatalf("unavailable keys authorized protected work: %v", err)
				}
			}
			if requests != requestsAfterFailure {
				t.Fatalf("protected calls bypassed transient retry pacing: %d requests, want %d", requests, requestsAfterFailure)
			}
			afterVersion, saved, err := client.storage.Load()
			if err != nil || version != afterVersion || !reflect.DeepEqual(previous, saved) {
				t.Fatal("key availability changed the saved credential or its expiry")
			}
			if err := client.checkGeneration(generation); !errors.Is(err, ErrStaleResponse) {
				t.Fatal("unverified reply did not supersede prior access generation")
			}
			if cold {
				client.mu.Lock()
				client.state.retryAt = time.Now().Add(-time.Second)
				client.mu.Unlock()
				if _, err := client.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrDenied) || requests == requestsAfterFailure {
					t.Fatalf("elapsed retry did not recheck unavailable keys: %v, %d requests", err, requests)
				}
			}
			unavailable = false
			state, err = client.Refresh(context.Background())
			if err != nil || state.Access != AccessOnline || !state.Entitlements["export"] {
				t.Fatalf("key recovery did not verify fresh access: %+v, %v", state, err)
			}
		})
	}
}

func TestUnavailableKeysNeverSaveNewActivation(t *testing.T) {
	body, _, _ := signedGrantResponse(t, true)
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == jwksPath {
			return unavailableKeys(request), nil
		}
		return testResponse(request, http.StatusOK, body), nil
	})
	client := testClient(t, &MemoryStorage{}, transport)
	if _, err := client.Activate(context.Background(), "synthetic-key", "operation_123456"); !errors.Is(err, ErrTransient) {
		t.Fatalf("unavailable activation verification: %v", err)
	}
	assertLocalContext(t, client, "")
}

func TestQueuedAutomaticRefreshRespectsTransientPacing(t *testing.T) {
	body, _, jwks := signedGrantResponse(t, false)
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseFirst := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseFirst)
	var validations atomic.Int32
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == jwksPath {
			return testResponse(request, http.StatusOK, jwks), nil
		}
		if validations.Add(1) == 1 {
			close(started)
			<-release
			return unavailableKeys(request), nil
		}
		return testResponse(request, http.StatusOK, body), nil
	})
	client := testClient(t, &MemoryStorage{}, transport)
	installTestContext(t, client, "old", false)
	client = testClient(t, client.storage, transport)
	first, queued := make(chan error, 1), make(chan error, 1)
	go func() { _, err := client.Refresh(context.Background()); first <- err }()
	waitSignal(t, started)
	go func() { _, err := client.refresh(context.Background(), true); queued <- err }()
	releaseFirst()
	if err := waitError(t, first); !errors.Is(err, ErrTransient) {
		t.Fatalf("first refresh: %v, want transient", err)
	}
	if err := waitError(t, queued); err != nil || validations.Load() != 1 {
		t.Fatalf("queued automatic refresh bypassed pacing: %v, %d validations", err, validations.Load())
	}
	if _, err := client.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrDenied) || validations.Load() != 1 {
		t.Fatalf("protected access retried or authorized without a grant: %v, %d validations", err, validations.Load())
	}
	if state, err := client.Refresh(context.Background()); err != nil || state.Access != AccessOnline || validations.Load() != 2 {
		t.Fatalf("explicit refresh did not recover access: %+v, %v, %d validations", state, err, validations.Load())
	}
}

func TestInvalidKeysAndSignaturesRemainTerminal(t *testing.T) {
	for _, kind := range []string{"malformed", "unknown_key", "wrong_signature", "tls", "denial"} {
		t.Run(kind, func(t *testing.T) {
			body, _, _ := signedGrantResponse(t, false)
			_, _, otherKeys := signedGrantResponse(t, false)
			transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != jwksPath {
					return testResponse(request, http.StatusOK, body), nil
				}
				switch kind {
				case "malformed":
					return testResponse(request, http.StatusOK, `{"keys":[{}]}`), nil
				case "unknown_key":
					return testResponse(request, http.StatusOK, strings.ReplaceAll(otherKeys, "lifecycle-test", "other-key")), nil
				case "tls":
					return nil, x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
				case "denial":
					return testResponse(request, http.StatusForbidden, `{"error":{"code":"licence_revoked","message":"Denied","request_id":"request"}}`), nil
				default:
					return testResponse(request, http.StatusOK, otherKeys), nil
				}
			})
			client := testClient(t, &MemoryStorage{}, transport)
			installTestContext(t, client, "old", true)
			expected := ErrInvalidResponse
			if kind == "tls" {
				expected = ErrTransportSecurity
			} else if kind == "denial" {
				expected = ErrDenied
			}
			if _, err := client.Refresh(context.Background()); !errors.Is(err, expected) {
				t.Fatalf("verification failure: %v, want %v", err, expected)
			}
			assertLocalContext(t, client, "")
		})
	}
}

func TestUnavailableKeysCannotUndoInvalidation(t *testing.T) {
	for _, invalidation := range []string{"logout", "shared_storage", "cancellation"} {
		t.Run(invalidation, func(t *testing.T) {
			body, _, _ := signedGrantResponse(t, false)
			started, released := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(released) }) }
			t.Cleanup(release)
			transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != jwksPath {
					return testResponse(request, http.StatusOK, body), nil
				}
				close(started)
				<-released
				return unavailableKeys(request), nil
			})
			client := testClient(t, &MemoryStorage{}, transport)
			installTestContext(t, client, "old", false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := client.Refresh(ctx); result <- err }()
			waitSignal(t, started)
			expected, current := ErrStaleResponse, ""
			switch invalidation {
			case "logout":
				if err := client.Logout(); err != nil {
					t.Fatal(err)
				}
			case "shared_storage":
				if _, err := client.storage.Invalidate(); err != nil {
					t.Fatal(err)
				}
			case "cancellation":
				cancel()
				expected, current = ErrCancelled, "old"
			}
			release()
			if err := waitError(t, result); !errors.Is(err, expected) {
				t.Fatalf("late key failure: %v", err)
			}
			assertLocalContext(t, client, current)
		})
	}
}

func TestVerificationBudgetExpiryClearsAuthorityWithoutSavingReply(t *testing.T) {
	body, _, jwks := signedGrantResponse(t, false)
	budget, cancel := context.WithCancel(context.Background())
	defer cancel()
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		cancel()
		return testResponse(request, http.StatusOK, jwks), nil
	})
	client := testClient(t, &MemoryStorage{}, transport)
	installTestContext(t, client, "old", true)
	previous := cloneCredential(client.state.credential)
	generation, _ := client.generation()
	started, _ := captureStart()
	if _, err := client.accept(context.Background(), budget, []byte(body), nil, generation, previous, "", started); !errors.Is(err, ErrTransient) {
		t.Fatalf("verification budget cancellation: %v", err)
	}
	state, err := client.Snapshot()
	if err != nil || state.Access != AccessRefreshRequired || len(state.Entitlements) != 0 || state.ExpiresAt != nil {
		t.Fatalf("budget expiry retained authority: %+v, %v", state, err)
	}
	_, saved, err := client.storage.Load()
	if err != nil || !reflect.DeepEqual(saved, previous) {
		t.Fatal("budget expiry changed saved credential")
	}
	if client.state.nextRetry <= 1800000000 || client.state.nextRetry > 1800000000+int64(time.Minute/time.Second) {
		t.Fatal("verification retry lost its existing backoff")
	}
}
