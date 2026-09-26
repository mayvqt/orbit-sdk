//go:build linux || windows

package orbit

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const nativeGrantLifetime = 30 * time.Second

func readNativeClock(t *testing.T, read func() (time.Duration, error)) time.Duration {
	t.Helper()
	value, err := read()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func nativeSleepReply(t *testing.T, key *ecdsa.PrivateKey, offline bool) string {
	t.Helper()
	now := time.Now().Unix()
	expires := now + int64(nativeGrantLifetime/time.Second)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://orbit.example.test", "aud": "orbit:app:test", "sub": "licence", "jti": "sleep_fixture",
		"iat": now, "nbf": now, "exp": expires, "application_id": "app", "environment_id": "test",
		"activation_id": "activation", "installation_id": "installation_1234", "binding_mode": "none",
		"fingerprint": nil, "fingerprint_provider": nil, "policy_version": 1, "entitlements": map[string]bool{"export": true},
		"refresh_after": expires, "offline_allowed": offline, "licence_expires_at": nil,
	})
	token.Header["typ"] = "orbit-access+jwt"
	token.Header["kid"] = "sleep_fixture"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	credential := strings.Repeat("s", 43)
	reply, err := json.Marshal(grantReply{ActivationID: "activation", InstallationID: "installation_1234",
		Credential: &credential, CredentialExpiresAt: optionalString(time.Unix(now+86400, 0).UTC().Format(time.RFC3339)),
		Grant: &signed, ServerTime: time.Unix(now, 0).UTC().Format(time.RFC3339), BindingMode: "none"})
	if err != nil {
		t.Fatal(err)
	}
	return string(reply)
}

func TestNativeGrantExpiresAcrossSuspend(t *testing.T) {
	opt := os.Getenv("ORBIT_NATIVE_GRANT_SUSPEND_TEST")
	if opt == "" {
		t.Skip("requires explicit opt-in and actual native sleep")
	}
	if opt != "1" {
		t.Fatal("ORBIT_NATIVE_GRANT_SUSPEND_TEST must be 1")
	}
	type fixture struct {
		client      *Client
		offline     bool
		denied      atomic.Int32
		activations atomic.Int32
		keys        atomic.Int32
	}
	var blocked atomic.Bool
	var fixtures []*fixture
	for _, offline := range []bool{false, true} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		jwks, err := json.Marshal(map[string]any{"keys": []jsonWebKey{{KeyType: "EC", Curve: "P-256", Algorithm: "ES256", Purpose: "sig", KeyID: "sleep_fixture",
			X: base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}}})
		if err != nil {
			t.Fatal(err)
		}
		fixture := &fixture{offline: offline}
		transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
			if blocked.Load() {
				fixture.denied.Add(1)
				return testResponse(request, 503, `{"error":{"code":"service_unavailable","message":"Synthetic outage","request_id":"sleep_fixture"}}`), nil
			}
			switch {
			case request.Method == http.MethodPost && request.URL.Path == clientPrefix+"activations":
				if fixture.activations.Add(1) != 1 {
					t.Fatal("Unexpected repeat activation")
				}
				return testResponse(request, 200, nativeSleepReply(t, key, offline)), nil
			case request.Method == http.MethodGet && request.URL.Path == jwksPath:
				fixture.keys.Add(1)
				return testResponse(request, 200, string(jwks)), nil
			default:
				t.Fatal("Unexpected synthetic grant request")
				return nil, ErrInvalidResponse
			}
		})
		fixture.client, err = NewClient(Config{ApplicationID: "app", EnvironmentID: "test", Issuer: "https://orbit.example.test"}, Device{InstallationID: "installation_1234"}, transport)
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, fixture)
	}
	activeStart := readNativeClock(t, nativeAwakeClock)
	start := readNativeClock(t, elapsedClock)
	for _, fixture := range fixtures {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		accepted, err := fixture.client.Activate(ctx, "synthetic licence", "sleep_operation_1234")
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if accepted.Access != AccessOnline || accepted.OfflineAllowed != fixture.offline || fixture.keys.Load() != 1 {
			t.Fatal("Signed grant was not accepted through activation and key discovery")
		}
	}
	blocked.Store(true)
	for _, fixture := range fixtures {
		accepted, err := fixture.client.RequireAccess(context.Background(), "export")
		if err != nil || accepted.Access != AccessOnline || !accepted.Entitlements["export"] || fixture.denied.Load() != 0 {
			t.Fatal("Positive protected access before sleep failed")
		}
	}
	writer := bufio.NewWriter(os.Stdout)
	fmt.Fprintln(writer, "READY: strict-online and offline-allowed grants accepted; refresh blocked. Suspend immediately for at least 45 seconds, then press Enter after resume.")
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal("EOF/read failure is not a resume acknowledgement")
	}
	elapsed := readNativeClock(t, elapsedClock) - start
	active := readNativeClock(t, nativeAwakeClock) - activeStart
	if elapsed < 0 || active < 0 || elapsed-active < 45*time.Second {
		t.Fatal("At least 45 seconds of actual native sleep required")
	}
	if active >= nativeGrantLifetime {
		t.Fatal("Too much awake time; expiry during sleep was not established")
	}
	assertExpired := func(client *Client) {
		t.Helper()
		snapshot, err := client.Snapshot()
		if err != nil || snapshot.Access != AccessExpired || len(snapshot.Entitlements) != 0 || snapshot.RemainingOfflineSeconds != 0 {
			t.Fatal("Expired grant retained access or entitlements")
		}
	}
	for _, fixture := range fixtures {
		assertExpired(fixture.client)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := fixture.client.RequireAccess(ctx, "export")
		cancel()
		var denied *Error
		if !errors.As(err, &denied) || denied.Kind != Denied || denied.Code != "access_unavailable" || fixture.denied.Load() == 0 {
			t.Fatal("Expired protected access did not deny after blocked refresh")
		}
		assertExpired(fixture.client)
	}
	fmt.Fprintf(os.Stdout, "PASS: both signed grants expired during native sleep; access and entitlements denied. elapsed=%s awake=%s sleep=%s\n", elapsed, active, elapsed-active)
}
