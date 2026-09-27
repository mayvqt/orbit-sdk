package orbit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type installedFixture struct {
	t                          testing.TB
	key                        *ecdsa.PrivateKey
	mode                       atomic.Int32 // 0 online, 1 outage, 2 denied, 3 malformed, 4 missing expiry, 5 finite expiry, 6 app version unsupported
	validation                 atomic.Int32
	activation                 atomic.Int32
	accountActivation          atomic.Int32
	loseFirstAccountActivation atomic.Bool
	malformedOwnedLicences     atomic.Bool
	loginFailures              atomic.Int32
	mu                         sync.Mutex
	operations                 []string
	previous                   string
	lastBody                   map[string]any
	clientHeaders              []string
	updateAvailable            any
	stateDirectory             string
	offline                    bool
	floating                   bool
	sessionStarts              atomic.Int32
	sessionRenews              atomic.Int32
	sessionEnds                atomic.Int32
	sessionCapacityDenied      atomic.Bool
	sessionRenewDenied         atomic.Bool
	sessionRenewTransient      atomic.Bool
	sessionRenewSequence       []int64
	sessionRenewIDs            []string
	sessionRenewEntered        chan struct{}
	sessionRenewRelease        chan struct{}
	sessionRenewOnce           sync.Once
	sessionStartEntered        chan struct{}
	sessionStartRelease        chan struct{}
	sessionStartOnce           sync.Once
}

func installedTestTempDir(t testing.TB) string {
	t.Helper()
	path := t.TempDir()
	if runtime.GOOS != "darwin" {
		return path
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve temporary test directory: %v", err)
	}
	return canonical
}

func newInstalledFixture(t testing.TB, offline bool) *installedFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &installedFixture{t: t, key: key, offline: offline}
}
func newFloatingFixture(t testing.TB) *installedFixture {
	f := newInstalledFixture(t, false)
	f.floating = true
	return f
}
func installedOptions(path string) Options {
	return Options{StatePath: path, BindingMode: BindingDisabled}
}
func (f *installedFixture) open(path string) (*Client, error) {
	return f.openWith(path, installedOptions(path))
}
func (f *installedFixture) openWith(path string, options Options) (*Client, error) {
	transport := testTransport(f.t, f.respond)
	return openInstalled(context.Background(), testAppKey(), options, transport)
}
func (f *installedFixture) respond(request *http.Request) (*http.Response, error) {
	if request.URL.Path == jwksPath {
		if f.floating && f.stateDirectory != "" && runtime.GOOS != "windows" {
			state, err := os.ReadFile(filepath.Join(f.stateDirectory, "orbit-storage.bin"))
			if err != nil || !strings.Contains(string(state), strings.Repeat("c", 43)) {
				f.t.Errorf("floating activation credential was not durable before session JWKS lookup: %v", err)
			}
		}
		kid := "installed-test"
		if f.floating {
			kid = "test-fixture"
		}
		data, _ := json.Marshal(map[string]any{"keys": []jsonWebKey{{KeyType: "EC", Curve: "P-256", Algorithm: "ES256", Purpose: "sig", KeyID: kid, X: base64.RawURLEncoding.EncodeToString(f.key.X.FillBytes(make([]byte, 32))), Y: base64.RawURLEncoding.EncodeToString(f.key.Y.FillBytes(make([]byte, 32)))}}})
		return testResponse(request, 200, string(data)), nil
	}
	if request.Method == http.MethodGet && request.URL.Path == clientPrefix+"licences" {
		if f.malformedOwnedLicences.Swap(false) {
			return testResponse(request, 200, `{malformed`), nil
		}
		return testResponse(request, 200, `{"items":[],"next_cursor":null}`), nil
	}
	f.mu.Lock()
	f.clientHeaders = append(f.clientHeaders, request.Header.Get("Orbit-Client"))
	f.mu.Unlock()
	var body map[string]any
	if json.NewDecoder(request.Body).Decode(&body) != nil {
		f.t.Error("invalid request")
	}
	f.mu.Lock()
	f.lastBody = body
	f.mu.Unlock()
	sessionRoot := clientPrefix + "activations/activation/sessions"
	if request.URL.Path == sessionRoot {
		f.sessionStarts.Add(1)
		if f.sessionStartEntered != nil {
			f.sessionStartOnce.Do(func() { close(f.sessionStartEntered) })
			<-f.sessionStartRelease
		}
		if f.sessionCapacityDenied.Load() {
			return testResponse(request, http.StatusForbidden, `{"error":{"code":"concurrent_session_limit_reached","message":"Denied","request_id":"fixture"}}`), nil
		}
		id, _ := body["session_id"].(string)
		return testResponse(request, http.StatusOK, f.signedSessionReply(id, 1, body["installation_id"].(string))), nil
	}
	if request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, sessionRoot+"/") {
		switch {
		case strings.HasSuffix(request.URL.Path, "/end"):
			f.sessionEnds.Add(1)
			return testResponse(request, http.StatusNoContent, ""), nil
		case strings.HasSuffix(request.URL.Path, "/renew"):
			f.sessionRenews.Add(1)
			sequence, _ := body["sequence"].(float64)
			id := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, sessionRoot+"/"), "/renew")
			f.mu.Lock()
			f.sessionRenewSequence = append(f.sessionRenewSequence, int64(sequence))
			f.sessionRenewIDs = append(f.sessionRenewIDs, id)
			f.mu.Unlock()
			if entered, release := f.sessionRenewEntered, f.sessionRenewRelease; entered != nil && release != nil {
				f.sessionRenewOnce.Do(func() { close(entered) })
				select {
				case <-release:
				case <-request.Context().Done():
					return nil, request.Context().Err()
				}
			}
			if f.sessionRenewTransient.Load() {
				return testResponse(request, http.StatusServiceUnavailable, `{"error":{"code":"service_unavailable","message":"Unavailable","request_id":"fixture"}}`), nil
			}
			if f.sessionRenewDenied.Load() {
				return testResponse(request, http.StatusForbidden, `{"error":{"code":"session_ended","message":"Denied","request_id":"fixture"}}`), nil
			}
			return testResponse(request, http.StatusOK, f.signedSessionReply(id, int64(sequence), body["installation_id"].(string))), nil
		}
	}
	if request.URL.Path == clientPrefix+"sessions" {
		if f.loginFailures.Load() > 0 && f.loginFailures.Add(-1) >= 0 {
			return testResponse(request, http.StatusUnauthorized, `{"error":{"code":"invalid_credentials","message":"Denied","request_id":"fixture"}}`), nil
		}
		username, _ := body["username"].(string)
		now := time.Now().UTC().Truncate(time.Second)
		reply, _ := json.Marshal(map[string]any{"customer": map[string]any{"id": "customer_" + username, "username": username, "email": username + "@example.test", "suspended": false, "created_at": now.Format(time.RFC3339)}, "session": strings.Repeat("s", 43), "expires_at": now.Add(time.Hour).Format(time.RFC3339)})
		return testResponse(request, 200, string(reply)), nil
	}
	activation := request.URL.Path == clientPrefix+"activations"
	if activation {
		f.activation.Add(1)
		f.mu.Lock()
		f.operations = append(f.operations, body["idempotency_key"].(string))
		f.previous, _ = body["previous_credential"].(string)
		f.mu.Unlock()
		if body["licence_id"] != nil {
			attempt := f.accountActivation.Add(1)
			if f.loseFirstAccountActivation.Load() {
				if attempt >= 3 {
					f.loseFirstAccountActivation.Store(false)
				}
				return nil, syscall.ECONNRESET
			}
		}
		if body["credential_mode"] != "persistent" {
			f.t.Error("persistent mode was not negotiated")
		}
	} else {
		f.validation.Add(1)
	}
	switch f.mode.Load() {
	case 1:
		response := testResponse(request, 503, `{"error":{"code":"service_unavailable","message":"Unavailable","request_id":"fixture"}}`)
		response.Header.Set("Retry-After", "30")
		return response, nil
	case 2:
		return testResponse(request, 403, `{"error":{"code":"licence_revoked","message":"Denied","request_id":"fixture"}}`), nil
	case 3:
		return testResponse(request, 200, `{"malformed":true}`), nil
	case 6:
		return testResponse(request, 403, `{"error":{"code":"app_version_unsupported","message":"Update required","request_id":"fixture"}}`), nil
	}
	now := time.Now().Unix()
	refresh := now + 60
	if f.offline {
		refresh = now + 900
	}
	expiry := now + 3600
	if !f.offline {
		expiry = now + 300
	}
	licenceID := "licence"
	if selected, ok := body["licence_id"].(string); ok {
		licenceID = selected
	}
	claims := jwt.MapClaims{"iss": "https://orbit.example.test", "aud": "orbit:app:test", "sub": licenceID, "jti": "grant", "iat": now, "nbf": now, "exp": expiry, "application_id": "app", "environment_id": "test", "activation_id": "activation", "installation_id": body["installation_id"], "binding_mode": "none", "policy_version": 1, "offline_allowed": f.offline, "refresh_after": refresh, "licence_expires_at": nil, "entitlements": map[string]bool{"export": true}}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"], token.Header["kid"] = "orbit-access+jwt", "installed-test"
	signed, err := token.SignedString(f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	reply := map[string]any{"activation_id": "activation", "installation_id": body["installation_id"], "credential": nil, "credential_expires_at": nil, "grant": signed, "server_time": time.Unix(now, 0).UTC().Format(time.RFC3339), "binding_mode": "none", "fingerprint_provider": body["fingerprint_provider"], "licence_expires_at": nil, "secret_replay_expired": false}
	if activation {
		reply["credential"] = strings.Repeat("c", 43)
	}
	if f.mode.Load() == 4 {
		delete(reply, "credential_expires_at")
	}
	if f.updateAvailable != nil {
		reply["update_available"] = f.updateAvailable
	}
	if f.mode.Load() == 5 {
		reply["credential_expires_at"] = time.Unix(now+86400, 0).UTC().Format(time.RFC3339)
	}
	if f.floating {
		reply["grant"] = nil
		reply["licence_id"] = licenceID
		reply["session_required"] = true
	}
	encoded, _ := json.Marshal(reply)
	return testResponse(request, 200, string(encoded)), nil
}

func (f *installedFixture) signedSessionReply(id string, sequence int64, installation string) string {
	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"iss": "https://orbit.example.test", "aud": "orbit-session:app:test", "sub": "licence",
		"jti": fmt.Sprintf("session_grant_%d", sequence), "iat": now, "nbf": now, "exp": now + 120,
		"application_id": "app", "environment_id": "test", "activation_id": "activation",
		"installation_id": installation, "binding_mode": "none", "policy_version": 1,
		"entitlements": map[string]bool{"export": true}, "refresh_after": now + 60,
		"offline_allowed": false, "licence_expires_at": nil, "session_id": id,
		"session_sequence": sequence,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"], token.Header["kid"] = "orbit-session+jwt", "test-fixture"
	signed, err := token.SignedString(f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	return fmt.Sprintf(`{"session_id":%q,"sequence":%d,"expires_at":%q,"server_time":%q,"grant":%q}`,
		id, sequence, time.Unix(now+120, 0).UTC().Format(time.RFC3339), time.Unix(now, 0).UTC().Format(time.RFC3339), signed)
}
func mustInstalledOpen(t *testing.T, f *installedFixture, path string) *Client {
	t.Helper()
	client, err := f.open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}
func mustInstalledActivate(t *testing.T, c *Client) {
	t.Helper()
	snapshot, err := c.Activate(context.Background(), "synthetic-key")
	if err != nil || snapshot.Access != AccessOnline {
		t.Fatalf("activation: %v, %v", snapshot.Access, err)
	}
}
func TestInstalledActivationAndOnlineRestart(t *testing.T) {
	f := newInstalledFixture(t, true)
	path := filepath.Join(installedTestTempDir(t), "state")
	c := mustInstalledOpen(t, f, path)
	id := c.device.InstallationID
	if _, err := c.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrNotActivated) {
		t.Fatal(err)
	}
	mustInstalledActivate(t, c)
	if c.state.credential.CredentialExpiresAt != 0 {
		t.Fatal("persistent credential gained a fixed expiry")
	}
	if c.Close() != nil {
		t.Fatal("close failed")
	}
	c = mustInstalledOpen(t, f, path)
	if c.device.InstallationID != id || f.activation.Load() != 1 || f.validation.Load() != 1 {
		t.Fatal("restart did not reuse the installation credential")
	}
	if _, err := c.RequireAccess(context.Background(), "export"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RequireAccess(context.Background(), "missing"); !errors.Is(err, ErrFeatureUnavailable) {
		t.Fatal(err)
	}
}

func TestInstalledMachineFingerprintMismatchRotatesInstallationAndClearsAuthority(t *testing.T) {
	f := newInstalledFixture(t, true)
	path := filepath.Join(installedTestTempDir(t), "state")
	first := Options{StatePath: path, BindingMode: BindingCustom, Fingerprint: strings.Repeat("a", 64), FingerprintProvider: "custom:test-device"}
	client, err := f.openWith(path, first)
	if err != nil {
		t.Fatal(err)
	}
	oldInstallation := client.device.InstallationID
	mustInstalledActivate(t, client)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	f.mode.Store(1)
	second := first
	second.Fingerprint = strings.Repeat("b", 64)
	client, err = f.openWith(path, second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if client.device.InstallationID == oldInstallation {
		t.Fatal("changed machine identity retained the old installation ID")
	}
	if client.installed.record.Credential != nil || client.installed.record.Access != nil || client.installed.record.Pending != nil {
		t.Fatal("changed machine identity retained old credential, grant, or pending operation")
	}
	state, err := client.Snapshot()
	if err != nil || state.Access != AccessDenied || state.HasFeature("export") || f.validation.Load() != 0 {
		t.Fatalf("changed identity restored cached authority or tried the old credential: %+v, validations=%d, %v", state, f.validation.Load(), err)
	}
}

func TestEnsureAccessDoesNotPromptDuringOutage(t *testing.T) {
	f := newInstalledFixture(t, false)
	path := filepath.Join(installedTestTempDir(t), "state")
	client := mustInstalledOpen(t, f, path)
	mustInstalledActivate(t, client)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	f.mode.Store(1)
	client = mustInstalledOpen(t, f, path)
	prompted := false
	_, err := client.EnsureAccess(context.Background(), "export", func(context.Context) (string, error) {
		prompted = true
		return "replacement-key", nil
	})
	if !errors.Is(err, ErrTransient) || prompted {
		t.Fatalf("outage prompted for activation or returned the wrong error: %v, prompted=%v", err, prompted)
	}
}

func TestEnsureAccessPromptsForMissingActivationOnly(t *testing.T) {
	f := newInstalledFixture(t, false)
	client := mustInstalledOpen(t, f, filepath.Join(installedTestTempDir(t), "state"))
	prompted := false
	state, err := client.EnsureAccess(context.Background(), "export", func(context.Context) (string, error) {
		prompted = true
		return "synthetic-key", nil
	})
	if err != nil || !prompted || !state.HasFeature("export") {
		t.Fatalf("missing activation was not prompted and activated: %+v, %v", state, err)
	}
	prompted = false
	_, err = client.EnsureAccess(context.Background(), "missing", func(context.Context) (string, error) {
		prompted = true
		return "replacement-key", nil
	})
	if !errors.Is(err, ErrFeatureUnavailable) || prompted {
		t.Fatalf("feature denial prompted for a new key: %v, prompted=%v", err, prompted)
	}
}
func TestInstalledRestartOfflineKeepsOriginalGrant(t *testing.T) {
	for _, offline := range []bool{false, true} {
		t.Run(map[bool]string{true: "offline", false: "strict"}[offline], func(t *testing.T) {
			f := newInstalledFixture(t, offline)
			path := filepath.Join(installedTestTempDir(t), "state")
			c := mustInstalledOpen(t, f, path)
			mustInstalledActivate(t, c)
			original := time.Unix(c.state.claims.ExpiresAt, 0).UTC()
			if c.Close() != nil {
				t.Fatal("close failed")
			}
			f.mode.Store(1)
			c = mustInstalledOpen(t, f, path)
			if f.validation.Load() != 1 {
				t.Fatal("cache exposed before online attempt")
			}
			result, err := c.RequireAccess(context.Background(), "export")
			if offline {
				if err != nil || result.Access != AccessOffline || result.ExpiresAt == nil || *result.ExpiresAt != original {
					t.Fatal("offline deadline moved or access failed", err)
				}
			} else if err == nil {
				t.Fatal("strict cache restored authority")
			}
		})
	}
}
func TestInstalledUncertainActivationIdentity(t *testing.T) {
	for _, failure := range []int32{1, 3, 4, 5} {
		t.Run(map[int32]string{1: "outage", 3: "malformed", 4: "missing_expiry", 5: "finite_expiry"}[failure], func(t *testing.T) {
			f := newInstalledFixture(t, true)
			f.mode.Store(failure)
			path := filepath.Join(installedTestTempDir(t), "state")
			c := mustInstalledOpen(t, f, path)
			if _, err := c.Activate(context.Background(), "synthetic-key"); err == nil {
				t.Fatal("invalid response accepted")
			}
			pending := *c.installed.record.Pending
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			c = mustInstalledOpen(t, f, path)
			if _, err := c.Activate(context.Background(), "different-key"); !errors.Is(err, ErrPendingActivation) {
				t.Fatal("changed uncertain input accepted", err)
			}
			f.mode.Store(0)
			mustInstalledActivate(t, c)
			if f.operations[0] != pending.OperationID || f.operations[1] != pending.OperationID || c.installed.record.Pending != nil {
				t.Fatal("uncertain identity not reused and committed")
			}
		})
	}
}
func TestInstalledPendingDenialExpiryAndResolution(t *testing.T) {
	f := newInstalledFixture(t, true)
	f.mode.Store(1)
	c := mustInstalledOpen(t, f, filepath.Join(installedTestTempDir(t), "state"))
	_, _ = c.Activate(context.Background(), "synthetic-key")
	c.installed.mu.Lock()
	r := c.installed.record
	p := *r.Pending
	p.CreatedAt -= 86400
	r.Pending = &p
	err := c.installed.writeLocked(r)
	c.installed.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Activate(context.Background(), "synthetic-key"); !errors.Is(err, ErrPendingActivationExpired) {
		t.Fatal(err)
	}
	if err := c.Logout(); err != nil {
		t.Fatal(err)
	}
	f.mode.Store(2)
	if _, err := c.Activate(context.Background(), "synthetic-key"); !errors.Is(err, ErrDenied) || c.installed.record.Pending != nil {
		t.Fatal("definitive denial retained pending identity", err)
	}
}

func TestInstalledAccountActivationRetryIsCustomerBoundAndSecretFree(t *testing.T) {
	t.Run("same customer resumes after restart", func(t *testing.T) {
		f := newInstalledFixture(t, false)
		f.loseFirstAccountActivation.Store(true)
		path := filepath.Join(installedTestTempDir(t), "state")
		client := mustInstalledOpen(t, f, path)
		if _, err := client.Login(context.Background(), "alice", "account-password-marker"); err != nil {
			t.Fatal(err)
		}
		if _, err := client.ActivateAccount(context.Background(), "licence_account"); !errors.Is(err, ErrTransient) {
			t.Fatalf("lost account activation did not stay uncertain: %v", err)
		}
		f.mu.Lock()
		if len(f.operations) != 3 {
			t.Fatalf("expected three bounded same-ID replay attempts, got %d", len(f.operations))
		}
		pendingID := f.operations[0]
		for _, id := range f.operations[1:] {
			if id != pendingID {
				t.Fatal("uncertain retries changed their operation ID")
			}
		}
		f.mu.Unlock()
		assertInstalledFileOmits(t, client, "account-password-marker", strings.Repeat("s", 43), "licence_key_marker")
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}

		client = mustInstalledOpen(t, f, path)
		f.loginFailures.Store(1)
		if _, err := client.Login(context.Background(), "alice", "account-password-marker"); !errors.Is(err, &Error{Kind: Denied, Code: "invalid_credentials"}) {
			t.Fatalf("synthetic failed login returned %v", err)
		}
		if _, err := client.Login(context.Background(), "alice", "account-password-marker"); err != nil {
			t.Fatal(err)
		}
		f.malformedOwnedLicences.Store(true)
		if _, err := client.OwnedLicences(context.Background(), ""); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("malformed owned-licences response returned %v", err)
		}
		if account, err := client.Account(); err != nil || account != nil {
			t.Fatalf("failed account request retained a login session: %+v, %v", account, err)
		}
		if _, err := client.CustomerSessionProof(); !errors.Is(err, ErrReauthenticationRequired) {
			t.Fatalf("failed account request retained session proof: %v", err)
		}
		state, err := client.Snapshot()
		if err != nil || state.Access != AccessDenied || state.HasFeature("export") {
			t.Fatalf("failed account request retained access authority: %+v, %v", state, err)
		}
		client.installed.mu.Lock()
		storedPendingID := ""
		if client.installed.record.Pending != nil {
			storedPendingID = client.installed.record.Pending.OperationID
		}
		client.installed.mu.Unlock()
		if storedPendingID != pendingID {
			t.Fatalf("unrelated account failure discarded uncertain activation ID: got %q want %q", storedPendingID, pendingID)
		}
		if _, err := client.Login(context.Background(), "alice", "account-password-marker"); err != nil {
			t.Fatal(err)
		}
		if _, err := client.ActivateAccount(context.Background(), "licence_account"); err != nil {
			t.Fatalf("same customer could not resume activation: %v", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.operations) != 4 || f.operations[3] != pendingID {
			t.Fatalf("restart did not reuse the pending operation ID: %#v", f.operations)
		}
		assertInstalledFileOmits(t, client, "account-password-marker", strings.Repeat("s", 43), "licence_key_marker")
	})

	t.Run("different customer cannot reuse pending activation", func(t *testing.T) {
		f := newInstalledFixture(t, false)
		f.loseFirstAccountActivation.Store(true)
		path := filepath.Join(installedTestTempDir(t), "state")
		client := mustInstalledOpen(t, f, path)
		if _, err := client.Login(context.Background(), "alice", "account-password-marker"); err != nil {
			t.Fatal(err)
		}
		if _, err := client.ActivateAccount(context.Background(), "licence_account"); !errors.Is(err, ErrTransient) {
			t.Fatalf("lost account activation did not stay uncertain: %v", err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		client = mustInstalledOpen(t, f, path)
		if _, err := client.Login(context.Background(), "bob", "another-password-marker"); err != nil {
			t.Fatal(err)
		}
		if _, err := client.ActivateAccount(context.Background(), "licence_account"); !errors.Is(err, ErrPendingActivation) {
			t.Fatalf("different customer reused the pending activation: %v", err)
		}
		f.mu.Lock()
		if len(f.operations) != 3 {
			t.Fatalf("conflicting customer caused another network mutation: %d attempts", len(f.operations))
		}
		f.mu.Unlock()
		assertInstalledFileOmits(t, client, "account-password-marker", "another-password-marker", strings.Repeat("s", 43), "licence_key_marker")
	})
}

func assertInstalledFileOmits(t *testing.T, client *Client, secrets ...string) {
	t.Helper()
	client.installed.mu.Lock()
	defer client.installed.mu.Unlock()
	data, err := client.installed.files.read()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(string(data), secret) {
			t.Fatalf("installed state persisted sensitive account input %q", secret)
		}
	}
}

func withInstalledFixtureFiles(t *testing.T, path string, scope installedScope, check func(installedFiles)) {
	t.Helper()
	encoded, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	files, _, created, err := openInstalledFiles(path, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := files.close(); err != nil {
			t.Error(err)
		}
	}()
	if created {
		t.Fatal("expected existing installed state")
	}
	check(files)
}

func TestInstalledExplicitPreviousCredential(t *testing.T) {
	f := newInstalledFixture(t, true)
	c := mustInstalledOpen(t, f, filepath.Join(installedTestTempDir(t), "state"))
	previous := strings.Repeat("p", 43)
	if _, err := c.ActivateWithPrevious(context.Background(), "synthetic-key", previous, "operation_123456"); err != nil || f.previous != previous {
		t.Fatal("fresh previous-bearer rebind rejected", err)
	}
}
func TestInstalledCacheClockAndSignatureFailClosed(t *testing.T) {
	for _, change := range []string{"rollback", "inconsistent", "signature", "expired"} {
		t.Run(change, func(t *testing.T) {
			f := newInstalledFixture(t, true)
			path := filepath.Join(installedTestTempDir(t), "state")
			c := mustInstalledOpen(t, f, path)
			mustInstalledActivate(t, c)
			c.mu.Lock()
			c.state.claims = nil
			c.state.anchor = nil
			c.mu.Unlock()
			c.installed.mu.Lock()
			r := c.installed.record
			a := *r.Access
			switch change {
			case "rollback":
				a.WallHighWater += 100
			case "inconsistent":
				a.ServerHighWater += 100
			case "signature":
				parts := strings.Split(a.JWS, ".")
				signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
				signature[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(signature)
				a.JWS = strings.Join(parts, ".")
			case "expired":
				a.ReceivedWallTime -= 7200
				a.WallHighWater -= 7200
			}
			r.Access = &a
			err := c.installed.writeLocked(r)
			c.installed.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			_ = c.Close()
			f.mode.Store(1)
			c = mustInstalledOpen(t, f, path)
			if _, err := c.RequireAccess(context.Background(), "export"); err == nil {
				t.Fatal("invalid cache granted access")
			}
			if c.installed.record.Access != nil {
				t.Fatal("invalid cache was not durably discarded")
			}
		})
	}
}
func TestInstalledAuthoritativeDenialClearsCache(t *testing.T) {
	f := newInstalledFixture(t, true)
	path := filepath.Join(installedTestTempDir(t), "state")
	c := mustInstalledOpen(t, f, path)
	mustInstalledActivate(t, c)
	_ = c.Close()
	f.mode.Store(2)
	if c, err := f.open(path); c != nil || !errors.Is(err, ErrDenied) {
		t.Fatal("denial restored access", err)
	}
	f.mode.Store(1)
	c = mustInstalledOpen(t, f, path)
	if c.state.credential != nil || c.installed.record.Access != nil {
		t.Fatal("denied cached authority survived restart")
	}
}
func TestInstalledCloseSettlesInflightAndReleasesLease(t *testing.T) {
	f := newInstalledFixture(t, true)
	path := filepath.Join(installedTestTempDir(t), "state")
	c := mustInstalledOpen(t, f, path)
	mustInstalledActivate(t, c)
	started := make(chan struct{})
	c.transport.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(started)
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	result := make(chan error, 1)
	go func() { _, err := c.Refresh(context.Background()); result <- err }()
	waitSignal(t, started)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := waitError(t, result); !errors.Is(err, ErrCancelled) {
		t.Fatal("close did not cancel request", err)
	}
	c = mustInstalledOpen(t, f, path)
	if _, err := c.RequireAccess(context.Background(), "export"); err != nil {
		t.Fatal(err)
	}
}
func TestInstalledCodecRejectsUnknownMissingDuplicateAndSecretFields(t *testing.T) {
	f := newInstalledFixture(t, true)
	c := mustInstalledOpen(t, f, filepath.Join(installedTestTempDir(t), "state"))
	mustInstalledActivate(t, c)
	r := c.installed.record
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), "synthetic-key") {
		t.Fatal("raw key persisted")
	}
	var object map[string]json.RawMessage
	_ = json.Unmarshal(data, &object)
	bad := [][]byte{append(append([]byte(nil), data[:len(data)-1]...), []byte(`,"format":2}`)...)}
	for _, name := range []string{"scope", "access", "credential", "pending_activation", "installation"} {
		copyObject := make(map[string]json.RawMessage)
		for k, v := range object {
			copyObject[k] = v
		}
		delete(copyObject, name)
		encoded, _ := json.Marshal(copyObject)
		bad = append(bad, encoded)
	}
	bad = append(bad, []byte(strings.Replace(string(data), `"credential":{`, `"credential":{"password":"secret",`, 1)))
	for _, encoded := range bad {
		if _, err := decodeInstalled(encoded, r.Scope, r.Provider); err == nil {
			t.Fatal("malformed installed record accepted")
		}
	}
}
func TestInstalledRequiresPrivateDedicatedState(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("Linux permissions exercised separately from Windows DACL tests")
	}
	f := newInstalledFixture(t, true)
	parent := installedTestTempDir(t)
	path := filepath.Join(parent, "state")
	c := mustInstalledOpen(t, f, path)
	if _, err := f.open(path); !errors.Is(err, ErrInstallationInUse) {
		t.Fatal("exclusive lease failed", err)
	}
	_ = c.Close()
	if err := os.Remove(filepath.Join(path, "orbit-storage.bin")); err != nil {
		t.Fatal(err)
	}
	if c, err := f.open(path); c != nil || !errors.Is(err, ErrStorage) {
		t.Fatal("missing initialized record silently reset", err)
	}
	unsafe := filepath.Join(parent, "unsafe")
	_ = os.Mkdir(unsafe, 0755)
	if c, err := f.open(unsafe); c != nil || !errors.Is(err, ErrStorage) {
		t.Fatal("unsafe directory repaired", err)
	}
	info, _ := os.Stat(unsafe)
	if info.Mode().Perm() != 0755 {
		t.Fatal("existing permissions changed")
	}
}

func TestInstalledCheckpointRejectsAndDiscardsInconsistentEvidence(t *testing.T) {
	for _, mode := range []string{"rollback", "progress"} {
		t.Run(mode, func(t *testing.T) {
			f := newInstalledFixture(t, true)
			path := filepath.Join(installedTestTempDir(t), "state")
			c := mustInstalledOpen(t, f, path)
			mustInstalledActivate(t, c)
			c.mu.Lock()
			c.installed.mu.Lock()
			r := c.installed.record
			a := *r.Access
			if mode == "rollback" {
				a.WallHighWater += 10
			} else {
				a.ReceivedWallTime -= 31
			}
			r.Access = &a
			err := c.installed.writeLocked(r)
			c.installed.mu.Unlock()
			if err != nil {
				c.mu.Unlock()
				t.Fatal(err)
			}
			err = c.checkpointLocked(true)
			c.mu.Unlock()
			if !errors.Is(err, ErrClockUncertain) || c.installed.record.Access != nil {
				t.Fatal("uncertain checkpoint retained cached authority", err)
			}
			_ = c.Close()
			f.mode.Store(1)
			c = mustInstalledOpen(t, f, path)
			if _, err := c.RequireAccess(context.Background(), "export"); err == nil {
				t.Fatal("discarded checkpoint cache returned after restart")
			}
		})
	}
}

func TestInstalledOutageDoesNotRequestAnotherActivation(t *testing.T) {
	f := newInstalledFixture(t, false)
	path := filepath.Join(installedTestTempDir(t), "state")
	c := mustInstalledOpen(t, f, path)
	mustInstalledActivate(t, c)
	_ = c.Close()
	f.mode.Store(1)
	c = mustInstalledOpen(t, f, path)
	if _, err := c.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrTransient) {
		t.Fatal("saved credential outage requested fresh activation", err)
	}
	if f.activation.Load() != 1 {
		t.Fatal("restart activated another credential")
	}
}

func TestInstalledInvalidValidationReplyKeepsCredential(t *testing.T) {
	f := newInstalledFixture(t, false)
	path := filepath.Join(installedTestTempDir(t), "state")
	c := mustInstalledOpen(t, f, path)
	mustInstalledActivate(t, c)
	_ = c.Close()
	f.mode.Store(3)
	if c, err := f.open(path); c != nil || !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("malformed validation reply: %v", err)
	}
	f.mode.Store(0)
	c = mustInstalledOpen(t, f, path)
	f.mode.Store(3)
	if _, err := c.Refresh(context.Background()); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("malformed refresh: %v", err)
	}
	prompted := false
	_, err := c.EnsureAccess(context.Background(), "export", func(context.Context) (string, error) {
		prompted = true
		return "replacement-key", nil
	})
	if !errors.Is(err, ErrInvalidResponse) || prompted || c.installed.record.Access != nil {
		t.Fatalf("paced failure prompted or kept cached access: %v, prompted=%v", err, prompted)
	}
	f.mode.Store(0)
	if _, err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RequireAccess(context.Background(), "export"); err != nil || f.activation.Load() != 1 {
		t.Fatalf("saved credential did not recover: %v, activations=%d", err, f.activation.Load())
	}
}

func TestInstalledNameResolutionFailureKeepsCredential(t *testing.T) {
	for _, temporary := range []bool{true, false} {
		t.Run(fmt.Sprint("temporary=", temporary), func(t *testing.T) {
			f := newInstalledFixture(t, false)
			path := filepath.Join(installedTestTempDir(t), "state")
			c := mustInstalledOpen(t, f, path)
			mustInstalledActivate(t, c)
			_ = c.Close()
			lookup := &net.DNSError{Err: "lookup failed", Name: "orbit.example.test", IsTemporary: temporary, IsNotFound: !temporary}
			transport := testTransport(t, func(*http.Request) (*http.Response, error) { return nil, lookup })
			c, err := openInstalled(context.Background(), testAppKey(), installedOptions(path), transport)
			if err != nil {
				t.Fatalf("name resolution failure blocked open: %v", err)
			}
			prompted := false
			_, err = c.EnsureAccess(context.Background(), "export", func(context.Context) (string, error) {
				prompted = true
				return "replacement-key", nil
			})
			if !errors.Is(err, ErrTransient) || prompted {
				t.Fatalf("name resolution failure: %v, prompted=%v", err, prompted)
			}
			_ = c.Close()
			c = mustInstalledOpen(t, f, path)
			if _, err := c.RequireAccess(context.Background(), "export"); err != nil || f.activation.Load() != 1 {
				t.Fatalf("activation was lost: %v, activations=%d", err, f.activation.Load())
			}
		})
	}
}
