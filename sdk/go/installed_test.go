package orbit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type installedFixture struct {
	t          *testing.T
	key        *ecdsa.PrivateKey
	mode       atomic.Int32 // 0 online, 1 outage, 2 denied, 3 malformed, 4 missing expiry, 5 finite expiry
	validation atomic.Int32
	activation atomic.Int32
	mu         sync.Mutex
	operations []string
	previous   string
	offline    bool
}

func newInstalledFixture(t *testing.T, offline bool) *installedFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &installedFixture{t: t, key: key, offline: offline}
}
func installedConfig(path string) AppConfig {
	return AppConfig{APIOrigin: "https://orbit.example.test", Issuer: "https://orbit.example.test", ApplicationID: "app", EnvironmentID: "test", StatePath: path}
}
func (f *installedFixture) open(path string) (*Client, error) {
	transport := testTransport(f.t, f.respond)
	return openInstalled(context.Background(), installedConfig(path), transport)
}
func (f *installedFixture) respond(request *http.Request) (*http.Response, error) {
	if request.URL.Path == jwksPath {
		data, _ := json.Marshal(map[string]any{"keys": []jsonWebKey{{KeyType: "EC", Curve: "P-256", Algorithm: "ES256", Purpose: "sig", KeyID: "installed-test", X: base64.RawURLEncoding.EncodeToString(f.key.X.FillBytes(make([]byte, 32))), Y: base64.RawURLEncoding.EncodeToString(f.key.Y.FillBytes(make([]byte, 32)))}}})
		return testResponse(request, 200, string(data)), nil
	}
	var body map[string]any
	if json.NewDecoder(request.Body).Decode(&body) != nil {
		f.t.Error("invalid request")
	}
	activation := request.URL.Path == clientPrefix+"activations"
	if activation {
		f.activation.Add(1)
		f.mu.Lock()
		f.operations = append(f.operations, body["idempotency_key"].(string))
		f.previous, _ = body["previous_credential"].(string)
		f.mu.Unlock()
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
	claims := jwt.MapClaims{"iss": "https://orbit.example.test", "aud": "orbit:app:test", "sub": "licence", "jti": "grant", "iat": now, "nbf": now, "exp": expiry, "application_id": "app", "environment_id": "test", "activation_id": "activation", "installation_id": body["installation_id"], "fingerprint": nil, "fingerprint_provider": nil, "binding_mode": "none", "policy_version": 1, "offline_allowed": f.offline, "refresh_after": refresh, "licence_expires_at": nil, "entitlements": map[string]bool{"export": true}}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"], token.Header["kid"] = "orbit-access+jwt", "installed-test"
	signed, err := token.SignedString(f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	reply := map[string]any{"activation_id": "activation", "installation_id": body["installation_id"], "credential": nil, "credential_expires_at": nil, "grant": signed, "server_time": time.Unix(now, 0).UTC().Format(time.RFC3339), "binding_mode": "none", "fingerprint_provider": nil, "licence_expires_at": nil, "secret_replay_expired": false}
	if activation {
		reply["credential"] = strings.Repeat("c", 43)
	}
	if f.mode.Load() == 4 {
		delete(reply, "credential_expires_at")
	}
	if f.mode.Load() == 5 {
		reply["credential_expires_at"] = time.Unix(now+86400, 0).UTC().Format(time.RFC3339)
	}
	encoded, _ := json.Marshal(reply)
	return testResponse(request, 200, string(encoded)), nil
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
	path := filepath.Join(t.TempDir(), "state")
	c := mustInstalledOpen(t, f, path)
	id := c.device.InstallationID
	if _, err := c.RequireAccess(context.Background(), "export"); !errors.Is(err, &Error{Kind: Denied, Code: "access_unavailable"}) {
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
	if _, err := c.RequireAccess(context.Background(), "missing"); !errors.Is(err, &Error{Kind: Denied, Code: "feature_unavailable"}) {
		t.Fatal(err)
	}
}
func TestInstalledRestartOfflineKeepsOriginalGrant(t *testing.T) {
	for _, offline := range []bool{false, true} {
		t.Run(map[bool]string{true: "offline", false: "strict"}[offline], func(t *testing.T) {
			f := newInstalledFixture(t, offline)
			path := filepath.Join(t.TempDir(), "state")
			c := mustInstalledOpen(t, f, path)
			mustInstalledActivate(t, c)
			original := c.state.claims.ExpiresAt
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
				if err != nil || result.Access != AccessOffline || *result.ExpiresAt != original {
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
			path := filepath.Join(t.TempDir(), "state")
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
	c := mustInstalledOpen(t, f, filepath.Join(t.TempDir(), "state"))
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
func TestInstalledExplicitPreviousCredential(t *testing.T) {
	f := newInstalledFixture(t, true)
	c := mustInstalledOpen(t, f, filepath.Join(t.TempDir(), "state"))
	previous := strings.Repeat("p", 43)
	if _, err := c.ActivateWithPrevious(context.Background(), "synthetic-key", previous, "operation_123456"); err != nil || f.previous != previous {
		t.Fatal("fresh previous-bearer rebind rejected", err)
	}
}
func TestInstalledCacheClockAndSignatureFailClosed(t *testing.T) {
	for _, change := range []string{"rollback", "inconsistent", "signature", "expired"} {
		t.Run(change, func(t *testing.T) {
			f := newInstalledFixture(t, true)
			path := filepath.Join(t.TempDir(), "state")
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
	path := filepath.Join(t.TempDir(), "state")
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
	path := filepath.Join(t.TempDir(), "state")
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
	c := mustInstalledOpen(t, f, filepath.Join(t.TempDir(), "state"))
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
		if _, err := decodeInstalled(encoded, r.Scope, r.Provider, nil, nil); err == nil {
			t.Fatal("malformed installed record accepted")
		}
	}
}
func TestInstalledRequiresPrivateDedicatedState(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("Linux permissions exercised separately from Windows DACL tests")
	}
	f := newInstalledFixture(t, true)
	parent := t.TempDir()
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
			path := filepath.Join(t.TempDir(), "state")
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
	path := filepath.Join(t.TempDir(), "state")
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
