package orbit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testClient(t *testing.T, storage Storage, transport *Transport) *Client {
	t.Helper()
	client, err := NewClientWithStorage(Config{ApplicationID: "app", EnvironmentID: "test", Issuer: "https://orbit.example.test"}, Device{InstallationID: "installation_1234"}, transport, storage)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func installTestContext(t *testing.T, client *Client, customer string, offline bool) {
	t.Helper()
	start, err := captureStart()
	if err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.state.account = &accountSession{token: strings.Repeat("a", 43), account: Account{Customer: Customer{ID: customer, Username: "alice", Email: "alice@example.test"}, ExpiresAt: "2030-01-01T00:00:00Z"}}
	client.state.credential = &StoredCredential{ApplicationID: "app", EnvironmentID: "test", ActivationID: "activation_" + customer, LicenceID: "licence", InstallationID: "installation_1234", Credential: strings.Repeat("c", 43), CredentialExpiresAt: 1800003600}
	if err := client.storage.Save(client.state.storageVersion, *client.state.credential); err != nil {
		t.Fatal(err)
	}
	client.state.anchor = &timeAnchor{server: 1800000000, requestStart: start}
	client.state.claims = &grantClaims{ExpiresAt: 1800000300, RefreshAfter: 1800000060, OfflineAllowed: offline, Entitlements: map[string]bool{"export": true}}
	client.state.transient = offline
}

func waitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for controlled request")
	}
}

func waitError(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for operation")
		return nil
	}
}

func delayedTransport(t *testing.T, status int, body string) (*Transport, <-chan struct{}, func()) {
	t.Helper()
	started, released := make(chan struct{}), make(chan struct{})
	var startOnce, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(released) }) }
	t.Cleanup(release)
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		startOnce.Do(func() { close(started) })
		select {
		case <-released:
			return testResponse(request, status, body), nil
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	})
	return transport, started, release
}

func TestLateReleaseResultsCannotAffectNewContext(t *testing.T) {
	for _, operation := range []string{"deactivate", "logout"} {
		for _, denied := range []bool{false, true} {
			name := operation + "/success"
			if denied {
				name = operation + "/denial"
			}
			t.Run(name, func(t *testing.T) {
				status, body := http.StatusNoContent, ""
				if denied {
					status, body = http.StatusUnauthorized, `{"error":{"code":"invalid_credentials","message":"Denied","request_id":"request"}}`
				}
				transport, started, release := delayedTransport(t, status, body)
				client := testClient(t, &MemoryStorage{}, transport)
				installTestContext(t, client, "old", false)
				result := make(chan error, 1)
				go func() {
					if operation == "deactivate" {
						result <- client.Deactivate(context.Background(), "operation_123456")
					} else {
						result <- client.LogoutAccount(context.Background())
					}
				}()
				waitSignal(t, started)
				state, err := client.Snapshot()
				if err != nil || state.Access != AccessDenied {
					t.Fatalf("access was not cleared before networking: %+v, %v", state, err)
				}
				if err := client.Logout(); err != nil {
					t.Fatal(err)
				}
				installTestContext(t, client, "new", false)
				release()
				if err := waitError(t, result); !errors.Is(err, ErrStaleResponse) {
					t.Fatalf("late result: %v, want stale response", err)
				}
				account, err := client.Account()
				if err != nil || account == nil || account.Customer.ID != "new" {
					t.Fatalf("late result changed account: %+v, %v", account, err)
				}
				if _, err := client.RequireAccess(context.Background(), "export"); err != nil {
					t.Fatalf("late result changed current access: %v", err)
				}
			})
		}
	}
}

func TestSharedStorageInvalidationClearsAccount(t *testing.T) {
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		t.Error("local invalidation unexpectedly sent a request")
		return testResponse(request, http.StatusNoContent, ""), nil
	})
	storage := &MemoryStorage{}
	client := testClient(t, storage, transport)
	installTestContext(t, client, "customer", true)
	generation, err := client.generation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Invalidate(); err != nil {
		t.Fatal(err)
	}
	account, err := client.Account()
	if err != nil || account != nil {
		t.Fatalf("shared invalidation retained account: %+v, %v", account, err)
	}
	if err := client.checkGeneration(generation); !errors.Is(err, ErrStaleResponse) {
		t.Fatalf("shared invalidation did not supersede generation: %v", err)
	}
	state, err := client.Snapshot()
	if err != nil || state.Access != AccessDenied || len(state.Entitlements) != 0 {
		t.Fatalf("shared invalidation retained access: %+v, %v", state, err)
	}
}

type customerSessionProofStorage struct {
	MemoryStorage
	writes atomic.Int32
}

func (s *customerSessionProofStorage) Save(version uint64, credential StoredCredential) error {
	s.writes.Add(1)
	return s.MemoryStorage.Save(version, credential)
}

func (s *customerSessionProofStorage) Invalidate() (uint64, error) {
	s.writes.Add(1)
	return s.MemoryStorage.Invalidate()
}

func TestCustomerSessionProofIsExplicitRedactedAndLocallyInvalidated(t *testing.T) {
	for _, invalidation := range []string{"logout", "shared_storage"} {
		t.Run(invalidation, func(t *testing.T) {
			token := strings.Repeat("s", 43)
			var requests atomic.Int32
			transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
				requests.Add(1)
				if request.Method != http.MethodPost || request.URL.Path != clientPrefix+"sessions" {
					t.Error("unexpected proof-related transport operation")
				}
				return testResponse(request, http.StatusOK, `{"customer":{"id":"customer","username":"alice","email":"alice@example.test","suspended":false,"created_at":"2026-01-01T00:00:00Z"},"session":"`+token+`","expires_at":"2030-01-01T00:00:00Z"}`), nil
			})
			storage := &customerSessionProofStorage{}
			client := testClient(t, storage, transport)
			if proof, err := client.CustomerSessionProof(); proof != nil || !errors.Is(err, ErrReauthenticationRequired) {
				t.Fatal("absent session did not require reauthentication")
			}
			if requests.Load() != 0 || storage.writes.Load() != 0 {
				t.Fatal("absent proof acquisition performed transport or storage mutation")
			}
			if _, err := client.Login(context.Background(), "alice", "synthetic password"); err != nil {
				t.Fatal(err)
			}
			writes := storage.writes.Load()
			proof, err := client.CustomerSessionProof()
			if err != nil || proof == nil || proof.AuthorizationHeader() != "Bearer "+token {
				t.Fatal("explicit proof header did not match the logged-in session")
			}
			for _, value := range []any{proof, *proof} {
				for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%f", "%t"} {
					if fmt.Sprintf(verb, value) != "[Orbit customer session proof redacted]" {
						t.Fatalf("proof formatting was not constantly redacted for %s", verb)
					}
				}
				if encoded, err := json.Marshal(value); encoded != nil || !errors.Is(err, ErrConfiguration) {
					t.Fatal("proof JSON serialization did not refuse sensitive material")
				}
			}
			account, err := client.Account()
			if err != nil || account == nil {
				t.Fatal("logged-in account metadata was unavailable")
			}
			encoded, err := json.Marshal(account)
			if err != nil || strings.Contains(string(encoded), token) || strings.Contains(fmt.Sprintf("%+v", account), token) {
				t.Fatal("ordinary account metadata exposed the session token")
			}
			if requests.Load() != 1 || storage.writes.Load() != writes {
				t.Fatal("proof acquisition performed transport or storage mutation")
			}
			if invalidation == "shared_storage" {
				if err := testClient(t, storage, transport).Logout(); err != nil {
					t.Fatal(err)
				}
			} else if err := client.Logout(); err != nil {
				t.Fatal(err)
			}
			writes = storage.writes.Load()
			if proof, err := client.CustomerSessionProof(); proof != nil || !errors.Is(err, ErrReauthenticationRequired) {
				t.Fatal("invalidated session still provided proof")
			}
			if requests.Load() != 1 || storage.writes.Load() != writes {
				t.Fatal("invalidated proof acquisition performed transport or storage mutation")
			}
		})
	}
}

func TestSecurityFailureClearsOfflineGrant(t *testing.T) {
	for _, kind := range []string{"redirect", "tls"} {
		t.Run(kind, func(t *testing.T) {
			transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
				if kind == "tls" {
					return nil, x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
				}
				response := testResponse(request, http.StatusFound, "")
				response.Header.Set("Location", "https://untrusted.example.test/capture")
				return response, nil
			})
			client := testClient(t, &MemoryStorage{}, transport)
			installTestContext(t, client, "customer", true)
			if _, err := client.Refresh(context.Background()); err == nil || errors.Is(err, ErrTransient) {
				t.Fatalf("security failure was not terminal: %v", err)
			}
			state, err := client.Snapshot()
			if err != nil || state.Access != AccessDenied || len(state.Entitlements) != 0 {
				t.Fatalf("security failure retained offline access: %+v, %v", state, err)
			}
		})
	}
}

func signedGrantResponse(t *testing.T, activation bool) (string, grantKeys, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := grantClaims{
		Issuer: "https://orbit.example.test", Audience: "orbit:app:test", Subject: "licence", ID: "grant",
		IssuedAt: 1800000000, NotBefore: 1800000000, ExpiresAt: 1800000300,
		ApplicationID: "app", EnvironmentID: "test", ActivationID: "activation_old", InstallationID: "installation_1234",
		BindingMode: "none", PolicyVersion: 1, Entitlements: map[string]bool{"export": true}, RefreshAfter: 1800000060,
	}
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	var tokenClaims jwt.MapClaims
	if err := json.Unmarshal(encoded, &tokenClaims); err != nil {
		t.Fatal(err)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, tokenClaims)
	token.Header["typ"] = "orbit-access+jwt"
	token.Header["kid"] = "lifecycle-test"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	reply := grantReply{ActivationID: "activation_old", InstallationID: "installation_1234", CredentialExpiresAt: optionalString(time.Unix(1800003600, 0).UTC().Format(time.RFC3339)), Grant: &signed, ServerTime: time.Unix(1800000000, 0).UTC().Format(time.RFC3339), BindingMode: "none"}
	if activation {
		credential := strings.Repeat("r", 43)
		reply.Credential = &credential
	}
	encoded, err = json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []jsonWebKey{{KeyType: "EC", Curve: "P-256", Algorithm: "ES256", Purpose: "sig", KeyID: "lifecycle-test", X: base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded), grantKeys{"lifecycle-test": &key.PublicKey}, string(jwks)
}

func assertLocalContext(t *testing.T, client *Client, customer string) {
	t.Helper()
	account, err := client.Account()
	if err != nil {
		t.Fatal(err)
	}
	state, err := client.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	_, credential, err := client.storage.Load()
	if err != nil {
		t.Fatal(err)
	}
	if customer == "" {
		if account != nil || state.Access != AccessDenied || len(state.Entitlements) != 0 || credential != nil {
			t.Fatalf("invalidated context restored state: account=%+v access=%+v persisted=%v", account, state, credential != nil)
		}
		return
	}
	if account == nil || account.Customer.ID != customer || state.Access != AccessOnline || !state.Entitlements["export"] || credential == nil || credential.ActivationID != "activation_"+customer {
		t.Fatalf("current context was changed: account=%+v access=%+v persisted=%v", account, state, credential != nil)
	}
}

func TestLateAccessResultsCannotRestoreOrClearState(t *testing.T) {
	for _, operation := range []string{"activation", "validation", "login"} {
		for _, response := range []string{"success", "denial", "malformed"} {
			for _, next := range []string{"logout", "new_identity", "shared_invalidation"} {
				t.Run(operation+"/"+response+"/"+next, func(t *testing.T) {
					body, keys, _ := signedGrantResponse(t, operation == "activation")
					if operation == "login" {
						body = `{"customer":{"id":"late","username":"alice","email":"alice@example.test","suspended":false,"created_at":"2026-01-01T00:00:00Z"},"session":"` + strings.Repeat("s", 43) + `","expires_at":"2030-01-01T00:00:00Z"}`
					}
					status := http.StatusOK
					if response == "denial" {
						status, body = http.StatusForbidden, `{"error":{"code":"licence_revoked","message":"Denied","request_id":"request"}}`
					} else if response == "malformed" {
						body = `{"invalid":true}`
					}
					transport, started, release := delayedTransport(t, status, body)
					client := testClient(t, &MemoryStorage{}, transport)
					client.keys = keys
					installTestContext(t, client, "old", false)
					result := make(chan error, 1)
					go func() {
						var err error
						switch operation {
						case "activation":
							_, err = client.ActivateAccount(context.Background(), "licence", "operation_123456")
						case "validation":
							_, err = client.Refresh(context.Background())
						case "login":
							_, err = client.Login(context.Background(), "alice", "synthetic password")
						}
						result <- err
					}()
					waitSignal(t, started)
					if next == "shared_invalidation" {
						if _, err := client.storage.Invalidate(); err != nil {
							t.Fatal(err)
						}
					} else if err := client.Logout(); err != nil {
						t.Fatal(err)
					}
					current := ""
					if next == "new_identity" {
						current = "new"
						installTestContext(t, client, current, false)
					}
					assertLocalContext(t, client, current)
					release()
					if err := waitError(t, result); !errors.Is(err, ErrStaleResponse) {
						t.Fatalf("late result = %v, want stale response", err)
					}
					assertLocalContext(t, client, current)
				})
			}
		}
	}
}

func TestLogoutDuringGrantKeyFetchCannotPersistGrant(t *testing.T) {
	body, _, jwks := signedGrantResponse(t, true)
	started, released := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(released) }) }
	t.Cleanup(release)
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == jwksPath {
			close(started)
			<-released
			return testResponse(request, http.StatusOK, jwks), nil
		}
		return testResponse(request, http.StatusOK, body), nil
	})
	client := testClient(t, &MemoryStorage{}, transport)
	result := make(chan error, 1)
	go func() {
		_, err := client.Activate(context.Background(), "synthetic-key", "operation_123456")
		result <- err
	}()
	waitSignal(t, started)
	if err := client.Logout(); err != nil {
		t.Fatal(err)
	}
	release()
	if err := waitError(t, result); !errors.Is(err, ErrStaleResponse) {
		t.Fatalf("late verified grant = %v, want stale response", err)
	}
	assertLocalContext(t, client, "")
}

func TestCancellationDiscardsLateSuccess(t *testing.T) {
	for _, operation := range []string{"activation", "validation", "login"} {
		t.Run(operation, func(t *testing.T) {
			body, keys, _ := signedGrantResponse(t, operation == "activation")
			if operation == "login" {
				body = `{"customer":{"id":"late","username":"alice","email":"alice@example.test","suspended":false,"created_at":"2026-01-01T00:00:00Z"},"session":"` + strings.Repeat("s", 43) + `","expires_at":"2030-01-01T00:00:00Z"}`
			}
			started, released := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(released) }) }
			t.Cleanup(release)
			transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
				close(started)
				// Deliberately return success after cancellation: state correctness
				// must not depend on an adapter honoring its context promptly.
				<-released
				return testResponse(request, http.StatusOK, body), nil
			})
			client := testClient(t, &MemoryStorage{}, transport)
			client.keys = keys
			installTestContext(t, client, "old", false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "activation":
					_, err = client.Activate(ctx, "synthetic-key", "operation_123456")
				case "validation":
					_, err = client.Refresh(ctx)
				case "login":
					_, err = client.Login(ctx, "alice", "synthetic password")
				}
				result <- err
			}()
			waitSignal(t, started)
			cancel()
			release()
			if err := waitError(t, result); !errors.Is(err, ErrCancelled) {
				t.Fatalf("late cancelled success = %v, want cancelled", err)
			}
			current := ""
			if operation == "validation" {
				current = "old"
			}
			assertLocalContext(t, client, current)
		})
	}
}

func TestUnkeyedAccountMutationsAreNotRetried(t *testing.T) {
	for _, operation := range []string{"registration", "resend", "recovery", "email_change", "login"} {
		t.Run(operation, func(t *testing.T) {
			var requests atomic.Int32
			transport := fixtureTransport(t, func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"error":{"code":"service_unavailable","message":"Retry","request_id":"request"}}`)
			})
			client := testClient(t, &MemoryStorage{}, transport)
			installTestContext(t, client, "old", false)
			var err error
			switch operation {
			case "registration":
				_, err = client.Register(context.Background(), Registration{LicenceKey: "synthetic-key", Username: "alice", Email: "alice@example.test", Password: "synthetic password"})
			case "resend":
				err = client.ResendRegistration(context.Background(), &PendingRegistration{resendCredential: strings.Repeat("s", 43), applicationID: "app", environmentID: "test"})
			case "recovery":
				err = client.RequestPasswordRecovery(context.Background(), "alice@example.test")
			case "email_change":
				err = client.RequestEmailChange(context.Background(), "synthetic password", "new@example.test")
			case "login":
				_, err = client.Login(context.Background(), "alice", "synthetic password")
			}
			if !errors.Is(err, ErrTransient) || requests.Load() != 1 {
				t.Fatalf("unkeyed mutation = %v after %d requests", err, requests.Load())
			}
		})
	}
}

func TestUnrecognizedOutagesClearOfflineAccess(t *testing.T) {
	for _, fixture := range []struct {
		name, code string
		status     int
	}{
		{"unknown", "future_error", 503},
		{"denied", "licence_revoked", 503},
		{"unexpected_status", "service_unavailable", 502},
		{"mismatched_rate_limit", "service_unavailable", 429},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
				return testResponse(request, fixture.status, `{"error":{"code":"`+fixture.code+`","message":"Denied","request_id":"request"}}`), nil
			})
			client := testClient(t, &MemoryStorage{}, transport)
			installTestContext(t, client, "old", true)
			if _, err := client.Refresh(context.Background()); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("unrecognized outage allowed fallback: %v", err)
			}
			assertLocalContext(t, client, "")
		})
	}
}

func TestHTTPTransientMetadataPreservesOfflinePolicy(t *testing.T) {
	for _, offline := range []bool{false, true} {
		var requests atomic.Int32
		transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
			requests.Add(1)
			response := testResponse(request, 503, `{"error":{"code":"service_unavailable","message":"synthetic-secret","request_id":"refresh_reference"}}`)
			response.Header.Set("Retry-After", "30")
			return response, nil
		})
		client := testClient(t, &MemoryStorage{}, transport)
		installTestContext(t, client, "customer", offline)
		state, err := client.Refresh(context.Background())
		if offline {
			if err != nil || state.Access != AccessOffline {
				t.Fatal("authoritative transient lost permitted offline access")
			}
		} else {
			var failure *Error
			if !errors.Is(err, ErrTransient) || !errors.As(err, &failure) || failure.RequestID != "refresh_reference" || failure.Code != "service_unavailable" {
				t.Fatal("strict-online transient lost HTTP metadata")
			}
			state, err = client.Snapshot()
			if err != nil || state.Access == AccessOnline || state.Access == AccessOffline {
				t.Fatal("strict-online transient granted access")
			}
		}
		if requests.Load() != 1 {
			t.Fatal("Retry-After exceeded the operation budget")
		}
	}
}

func TestGatewayOutagePreservesCredentialForVerifiedRecovery(t *testing.T) {
	body, keys, _ := signedGrantResponse(t, false)
	gatewayUnavailable := true
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		if gatewayUnavailable {
			response := testResponse(request, http.StatusBadGateway, "Bad Gateway")
			response.Header.Set("Content-Type", "text/plain; charset=utf-8")
			return response, nil
		}
		return testResponse(request, http.StatusOK, body), nil
	})
	storage := &MemoryStorage{}
	client := testClient(t, storage, transport)
	client.keys = keys
	installTestContext(t, client, "old", false)
	version, saved, err := storage.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Refresh(context.Background()); !errors.Is(err, ErrTransient) {
		t.Fatalf("gateway outage returned %v, want transient", err)
	}
	state, err := client.Snapshot()
	if err != nil || state.Access == AccessOnline || state.Access == AccessOffline {
		t.Fatalf("gateway outage authorized protected access: %+v, %v", state, err)
	}
	afterVersion, after, err := storage.Load()
	if err != nil || afterVersion != version || !reflect.DeepEqual(after, saved) {
		t.Fatal("gateway outage changed the saved credential")
	}
	gatewayUnavailable = false
	state, err = client.Refresh(context.Background())
	if err != nil || state.Access != AccessOnline || !state.Entitlements["export"] {
		t.Fatalf("restored gateway did not verify fresh access: %+v, %v", state, err)
	}
}

func TestActivationAndValidationAcceptVerifiedWireResponses(t *testing.T) {
	activation, _, jwks := signedGrantResponse(t, true)
	var reply grantReply
	if err := json.Unmarshal([]byte(activation), &reply); err != nil {
		t.Fatal(err)
	}
	issuedCredential := *reply.Credential
	reply.Credential = nil
	validation, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	transport := fixtureTransport(t, func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		switch request.URL.Path {
		case clientPrefix + "activations":
			_, _ = io.WriteString(w, activation)
		case jwksPath:
			_, _ = io.WriteString(w, jwks)
		case clientPrefix + "activations/activation_old/validate":
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body["credential"] != issuedCredential {
				t.Errorf("validation did not use issued credential: %v", err)
			}
			_, _ = w.Write(validation)
		default:
			t.Errorf("unexpected route: %s", request.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	client := testClient(t, &MemoryStorage{}, transport)
	for _, operation := range []func() (Snapshot, error){
		func() (Snapshot, error) {
			return client.Activate(context.Background(), "synthetic-key", "operation_123456")
		},
		func() (Snapshot, error) { return client.Refresh(context.Background()) },
	} {
		state, err := operation()
		if err != nil || state.Access != AccessOnline || !state.Entitlements["export"] {
			t.Fatalf("verified wire result did not authorize: %+v, %v", state, err)
		}
		_, credential, err := client.storage.Load()
		if err != nil || credential == nil || credential.Credential != issuedCredential || credential.CredentialExpiresAt != 1800003600 {
			t.Fatalf("verified credential was not preserved: present=%v, %v", credential != nil, err)
		}
	}
	if requests.Load() != 3 {
		t.Fatalf("activation/validation sent %d requests, want activation + keys + validation", requests.Load())
	}
}

type invalidatingSaveStorage struct {
	MemoryStorage
}

func (s *invalidatingSaveStorage) Save(version uint64, credential StoredCredential) error {
	// Another context invalidates after the client's last Version check and
	// before its atomic write. Save must refuse this otherwise-valid grant.
	if _, err := s.Invalidate(); err != nil {
		return err
	}
	return s.MemoryStorage.Save(version, credential)
}

func TestConcurrentStorageInvalidationPreventsGrantWrite(t *testing.T) {
	body, keys, _ := signedGrantResponse(t, true)
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		return testResponse(request, http.StatusOK, body), nil
	})
	client := testClient(t, &invalidatingSaveStorage{}, transport)
	client.keys = keys
	if _, err := client.Activate(context.Background(), "synthetic-key", "operation_123456"); !errors.Is(err, ErrStaleResponse) {
		t.Fatalf("concurrent invalidation = %v, want stale response", err)
	}
	assertLocalContext(t, client, "")
}
