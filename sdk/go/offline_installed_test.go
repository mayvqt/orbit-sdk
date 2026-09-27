package orbit

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type offlineFailingInstalledFiles struct{ installedFiles }

func (offlineFailingInstalledFiles) write([]byte) error {
	return errors.New("synthetic durable write failure")
}

type offlineDelayedInstalledFiles struct {
	installedFiles
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (f *offlineDelayedInstalledFiles) write(data []byte) error {
	f.once.Do(func() {
		close(f.entered)
		<-f.release
	})
	return f.installedFiles.write(data)
}

func delayFirstOfflineWrite(t *testing.T, client *Client) (*offlineDelayedInstalledFiles, func()) {
	t.Helper()
	files := &offlineDelayedInstalledFiles{
		installedFiles: client.installed.files,
		entered:        make(chan struct{}),
		release:        make(chan struct{}),
	}
	client.installed.mu.Lock()
	client.installed.files = files
	client.installed.mu.Unlock()
	var once sync.Once
	release := func() { once.Do(func() { close(files.release) }) }
	t.Cleanup(release)
	return files, release
}

func TestClearOfflineAuthorityDoesNotMutatePriorRecord(t *testing.T) {
	token := "signed-offline-file"
	prior := installedRecord{Offline: &offlineRecord{JWS: &token, Sequence: 7}}
	next := prior
	clearOfflineAuthority(&next)
	if prior.Offline.JWS == nil || *prior.Offline.JWS != token {
		t.Fatal("clearing a copied record mutated the saved offline authority")
	}
	if next.Offline.JWS != nil || next.Offline.Sequence != prior.Offline.Sequence {
		t.Fatalf("cleared record did not preserve its sequence floor: %+v", next.Offline)
	}
}

func offlineFixture(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	keyBytes, err := os.ReadFile("../rust/tests/fixtures/es256-test-private.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		t.Fatal("offline signing fixture missing")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("offline fixture is not ES256")
	}
	data, err := os.ReadFile("../../contracts/sdk/offline-files.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		JWKS json.RawMessage `json:"jwks"`
	}
	if err = json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	return key, corpus.JWKS
}
func signOfflineFixture(t *testing.T, key *ecdsa.PrivateKey, installation string, sequence int64, issuance string, expiry int64) []byte {
	t.Helper()
	now := time.Now().Unix()
	claims := jwt.MapClaims{"ver": 1, "iss": "https://orbit.example.test", "aud": "orbit-offline:app:test", "sub": "licence", "jti": issuance, "iat": now, "nbf": now, "exp": expiry, "application_id": "app", "environment_id": "test", "activation_id": "activation", "installation_id": installation, "sequence": sequence, "binding_mode": "none", "policy_version": 1, "entitlements": map[string]bool{"export": true}}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"], token.Header["kid"] = "orbit-offline+jwt", "offline-test-fixture"
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(signed)
}
func openOfflineFixture(t *testing.T, path string, keys []byte, requests *atomic.Int32) *Client {
	t.Helper()
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		return testResponse(request, 503, `{}`), nil
	})
	client, err := openInstalled(context.Background(), testAppKey(), Options{StatePath: path, BindingMode: BindingDisabled, OfflineKeys: keys}, transport)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestInstalledOfflineImportRestartRenewalLogoutAndNoNetwork(t *testing.T) {
	key, jwks := offlineFixture(t)
	path := filepath.Join(installedTestTempDir(t), "offline-state")
	var requests atomic.Int32
	client := openOfflineFixture(t, path, jwks, &requests)
	request, err := client.OfflineRequest()
	if err != nil {
		t.Fatal(err)
	}
	if request.Format != "orbit-offline-request" || request.Version != 1 || request.AppKey != publicAppKey(testAppKey()) || request.InstallationID != client.device.InstallationID {
		t.Fatalf("bad offline request: %+v", request)
	}
	first := signOfflineFixture(t, key, client.device.InstallationID, 1, "offline_issue_first", time.Now().Unix()+86400)
	snapshot, err := client.ImportOfflineFile(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Access != AccessOffline || !snapshot.OfflineFileMode || !snapshot.HasFeature("export") {
		t.Fatalf("offline file not active: %+v", snapshot)
	}
	reordered := reorderAndSignOfflineVector(t, string(first), key, false)
	if _, err = client.ImportOfflineFile(context.Background(), []byte(reordered)); err != nil {
		t.Fatalf("reordered identical claims were rejected at equal sequence: %v", err)
	}
	changed := reorderAndSignOfflineVector(t, string(first), key, true)
	if _, err = client.ImportOfflineFile(context.Background(), []byte(changed)); !errors.Is(err, offlineError("offline_sequence")) {
		t.Fatalf("same issuance and sequence with changed claims was not rejected: %v", err)
	}
	if _, err = client.RequireAccess(context.Background(), "export"); err != nil {
		t.Fatal(err)
	}
	beforeReimport := client.state.offline.saved.TimeHighWater
	time.Sleep(1100 * time.Millisecond)
	if _, err = client.ImportOfflineFile(context.Background(), first); err != nil {
		t.Fatalf("same-file reimport: %v", err)
	}
	if client.state.offline.saved.TimeHighWater <= beforeReimport {
		t.Fatal("elapsed time was reset by same-file reimport")
	}
	if requests.Load() != 0 {
		t.Fatalf("offline guard made %d HTTP requests", requests.Load())
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	noKeyTransport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		return testResponse(request, 503, `{}`), nil
	})
	if _, err = openInstalled(context.Background(), testAppKey(), Options{StatePath: path, BindingMode: BindingDisabled}, noKeyTransport); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("saved offline file without configured trusted keys: %v", err)
	}
	client = openOfflineFixture(t, path, jwks, &requests)
	if _, err = client.RequireAccess(context.Background(), "export"); err != nil {
		t.Fatalf("restart did not restore offline access: %v", err)
	}
	second := signOfflineFixture(t, key, client.device.InstallationID, 2, "offline_issue_second", time.Now().Unix()+172800)
	if _, err = client.ImportOfflineFile(context.Background(), second); err != nil {
		t.Fatalf("renewal import: %v", err)
	}
	if _, err = client.ImportOfflineFile(context.Background(), first); err == nil {
		t.Fatal("older file was replayed")
	}
	conflict := signOfflineFixture(t, key, client.device.InstallationID, 2, "offline_issue_conflict", time.Now().Unix()+172800)
	if _, err = client.ImportOfflineFile(context.Background(), conflict); err == nil {
		t.Fatal("equal sequence with another issuance was accepted")
	}
	if err = client.Logout(); err != nil {
		t.Fatal(err)
	}
	if client.installed.record.Offline == nil || client.installed.record.Offline.JWS != nil {
		t.Fatal("logout discarded renewal floor or retained offline authority")
	}
	if _, err = client.ImportOfflineFile(context.Background(), first); err == nil {
		t.Fatal("logout forgot the sequence floor")
	}
	if requests.Load() != 0 {
		t.Fatalf("offline flow made %d HTTP requests", requests.Load())
	}
	_ = client.Close()
}

func TestInstalledOfflineClockUncertaintyCannotBeResetByReimport(t *testing.T) {
	key, jwks := offlineFixture(t)
	path := filepath.Join(installedTestTempDir(t), "offline-clock")
	var requests atomic.Int32
	client := openOfflineFixture(t, path, jwks, &requests)
	token := signOfflineFixture(t, key, client.device.InstallationID, 1, "offline_clock_issue", time.Now().Unix()+86400)
	if _, err := client.ImportOfflineFile(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	anchor := *client.state.offline.anchor
	client.state.offline.anchor.wall += 60
	if _, err := client.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrClockUncertain) {
		t.Fatalf("clock rollback decision: %v", err)
	}
	before := *client.state.offline.anchor
	if _, err := client.ImportOfflineFile(context.Background(), token); !errors.Is(err, ErrClockUncertain) {
		t.Fatalf("reimport reset uncertain clock: %v", err)
	}
	if client.state.offline.anchor.wall != before.wall || client.state.offline.anchor.elapsed != before.elapsed || anchor.server != before.server {
		t.Fatal("clock uncertainty replaced the original continuous anchor")
	}
	if requests.Load() != 0 {
		t.Fatalf("offline clock check made %d HTTP requests", requests.Load())
	}
	*client.state.offline.anchor = anchor
	if err := client.Logout(); err != nil {
		t.Fatalf("logout after clock recovery: %v", err)
	}
	if _, err := client.ImportOfflineFile(context.Background(), token); err != nil {
		t.Fatalf("reimport after clock recovery and logout: %v", err)
	}
	if !client.state.offline.authorized || requests.Load() != 0 {
		t.Fatal("recovery reimport failed or used the network")
	}
	_ = client.Close()
}

func TestInstalledOfflineAuthorityIsDurablyClearedBeforeFailedOnlineActivation(t *testing.T) {
	key, jwks := offlineFixture(t)
	path := filepath.Join(installedTestTempDir(t), "offline-switch")
	var requests atomic.Int32
	client := openOfflineFixture(t, path, jwks, &requests)
	token := signOfflineFixture(t, key, client.device.InstallationID, 1, "offline_switch_issue", time.Now().Unix()+86400)
	if _, err := client.ImportOfflineFile(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Activate(context.Background(), "synthetic-key"); !errors.Is(err, ErrTransient) {
		t.Fatalf("failed online activation: %v", err)
	}
	if client.installed.record.Offline == nil || client.installed.record.Offline.JWS != nil || client.installed.record.Offline.Sequence != 1 {
		t.Fatal("failed online switch restored offline authority or lost its floor")
	}
	prompted := false
	if _, err := client.EnsureAccess(context.Background(), "export", func(context.Context) (string, error) { prompted = true; return "another-key", nil }); !errors.Is(err, ErrTransient) || prompted {
		t.Fatalf("failed online switch retained authority or prompted: prompted=%v err=%v", prompted, err)
	}
	if requests.Load() != 3 {
		t.Fatalf("unexpected number of online retry attempts: %d", requests.Load())
	}
	_ = client.Close()
}

func TestInstalledOfflineExpiryDoesNotPromptOrRefresh(t *testing.T) {
	key, jwks := offlineFixture(t)
	path := filepath.Join(installedTestTempDir(t), "offline-expiry")
	var requests atomic.Int32
	client := openOfflineFixture(t, path, jwks, &requests)
	token := signOfflineFixture(t, key, client.device.InstallationID, 1, "offline_expiring_issue", time.Now().Unix()+86400)
	if _, err := client.ImportOfflineFile(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	client.state.offline.anchor.server = client.state.offline.claims.ExpiresAt
	if _, err := client.RequireAccess(context.Background(), "export"); !errors.Is(err, offlineError("offline_file_expired")) {
		t.Fatalf("expiry result: %v", err)
	}
	prompted := false
	if _, err := client.EnsureAccess(context.Background(), "export", func(context.Context) (string, error) { prompted = true; return "", nil }); err == nil || prompted {
		t.Fatalf("expired offline file prompted or succeeded: prompted=%v err=%v", prompted, err)
	}
	if requests.Load() != 0 {
		t.Fatalf("expired offline guard made %d HTTP requests", requests.Load())
	}
	_ = client.Close()
	client = openOfflineFixture(t, path, jwks, &requests)
	if _, err := client.RequireAccess(context.Background(), "export"); !errors.Is(err, offlineError("offline_file_expired")) {
		t.Fatalf("expired file was not expired after restart: %v", err)
	}
	prompted = false
	if _, err := client.EnsureAccess(context.Background(), "export", func(context.Context) (string, error) { prompted = true; return "", nil }); err == nil || prompted {
		t.Fatalf("expired restarted file prompted or succeeded: prompted=%v err=%v", prompted, err)
	}
	if requests.Load() != 0 {
		t.Fatalf("expired restarted guard made %d HTTP requests", requests.Load())
	}
	_ = client.Close()
}

func TestInstalledOfflineDowntimeCountsTowardExpiry(t *testing.T) {
	key, jwks := offlineFixture(t)
	path := filepath.Join(installedTestTempDir(t), "offline-downtime")
	var requests atomic.Int32
	client := openOfflineFixture(t, path, jwks, &requests)
	expires := time.Now().Unix() + 8
	token := signOfflineFixture(t, key, client.device.InstallationID, 1, "offline_downtime_issue", expires)
	snapshot, err := client.ImportOfflineFile(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ExpiresAt == nil {
		t.Fatal("offline file expiry missing")
	}
	deadline := *snapshot.ExpiresAt
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(deadline.Add(-2 * time.Second)); delay > 0 {
		time.Sleep(delay)
	}
	client = openOfflineFixture(t, path, jwks, &requests)
	if _, err = client.RequireAccess(context.Background(), "export"); err != nil {
		t.Fatalf("file expired during pre-expiry downtime: %v", err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if delay := time.Until(deadline.Add(time.Second)); delay > 0 {
		time.Sleep(delay)
	}
	client = openOfflineFixture(t, path, jwks, &requests)
	if _, err = client.RequireAccess(context.Background(), "export"); !errors.Is(err, offlineError("offline_file_expired")) {
		t.Fatalf("downtime did not consume the signed term: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("offline downtime checks made %d HTTP requests", requests.Load())
	}
	_ = client.Close()
}

func TestInstalledOfflineImportSamplesAfterDurableWriteAndHonorsCancellation(t *testing.T) {
	t.Run("expires during durable write", func(t *testing.T) {
		key, jwks := offlineFixture(t)
		path := filepath.Join(installedTestTempDir(t), "offline-delayed-expiry")
		var requests atomic.Int32
		client := openOfflineFixture(t, path, jwks, &requests)
		expires := time.Now().Unix() + 3
		file := signOfflineFixture(t, key, client.device.InstallationID, 1, "offline_delayed_expiry", expires)
		blocked, release := delayFirstOfflineWrite(t, client)
		result := make(chan struct {
			snapshot Snapshot
			err      error
		}, 1)
		go func() {
			snapshot, err := client.ImportOfflineFile(context.Background(), file)
			result <- struct {
				snapshot Snapshot
				err      error
			}{snapshot, err}
		}()
		<-blocked.entered
		if delay := time.Until(time.Unix(expires, 0)) + 100*time.Millisecond; delay > 0 {
			time.Sleep(delay)
		}
		release()
		outcome := <-result
		if outcome.err != nil || outcome.snapshot.Access != AccessExpired || outcome.snapshot.HasFeature("export") || len(outcome.snapshot.Entitlements) != 0 {
			t.Fatalf("delayed import exposed expired authority: snapshot=%+v err=%v", outcome.snapshot, outcome.err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("cancelled while durable write is queued", func(t *testing.T) {
		key, jwks := offlineFixture(t)
		path := filepath.Join(installedTestTempDir(t), "offline-cancelled-write")
		var requests atomic.Int32
		client := openOfflineFixture(t, path, jwks, &requests)
		file := signOfflineFixture(t, key, client.device.InstallationID, 1, "offline_cancelled_write", time.Now().Unix()+86400)
		blocked, release := delayFirstOfflineWrite(t, client)
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { _, err := client.ImportOfflineFile(ctx, file); result <- err }()
		<-blocked.entered
		cancel()
		release()
		if err := <-result; !errors.Is(err, ErrCancelled) {
			t.Fatalf("cancelled import result: %v", err)
		}
		if client.installed.record.Offline == nil || client.installed.record.Offline.JWS != nil || client.state.offline != nil || client.state.claims != nil {
			t.Fatal("cancelled durable import retained offline authority")
		}
		_ = client.Close()
	})
}

func TestInstalledOfflineImportRacingLogoutCannotRetainAuthority(t *testing.T) {
	key, jwks := offlineFixture(t)
	path := filepath.Join(installedTestTempDir(t), "offline-queued-logout")
	var requests atomic.Int32
	client := openOfflineFixture(t, path, jwks, &requests)
	file := signOfflineFixture(t, key, client.device.InstallationID, 1, "offline_queued_logout", time.Now().Unix()+86400)
	blocked, release := delayFirstOfflineWrite(t, client)
	importResult := make(chan error, 1)
	go func() { _, err := client.ImportOfflineFile(context.Background(), file); importResult <- err }()
	<-blocked.entered
	logoutStarted := make(chan struct{})
	logoutResult := make(chan error, 1)
	go func() {
		close(logoutStarted)
		logoutResult <- client.Logout()
	}()
	<-logoutStarted
	time.Sleep(20 * time.Millisecond)
	release()
	if err := <-importResult; err != nil {
		t.Fatalf("offline import racing logout: %v", err)
	}
	if err := <-logoutResult; err != nil {
		t.Fatalf("logout after serialized import: %v", err)
	}
	if client.installed.record.Offline == nil || client.installed.record.Offline.JWS != nil || client.state.offline != nil && client.state.offline.authorized {
		t.Fatal("import racing logout retained authority")
	}
	if requests.Load() != 0 {
		t.Fatalf("offline race made %d HTTP requests", requests.Load())
	}
	_ = client.Close()
}

func TestInstalledOfflineQueuedImportCancellationAndLogoutStayFenced(t *testing.T) {
	key, jwks := offlineFixture(t)
	var requests atomic.Int32
	client := openOfflineFixture(t, filepath.Join(installedTestTempDir(t), "offline-queued-fence"), jwks, &requests)
	first := signOfflineFixture(t, key, client.device.InstallationID, 1, "offline_queued_fence_first", time.Now().Unix()+86400)
	if _, err := client.ImportOfflineFile(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	file := signOfflineFixture(t, key, client.device.InstallationID, 2, "offline_queued_fence_next", time.Now().Unix()+172800)

	t.Run("cancellation", func(t *testing.T) {
		generation, err := client.generation()
		if err != nil {
			t.Fatal(err)
		}
		client.serial <- struct{}{}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			_, err := client.importOfflineFileWithGeneration(ctx, file, generation)
			result <- err
		}()
		cancel()
		if err := <-result; !errors.Is(err, ErrCancelled) {
			t.Fatalf("queued import cancellation: %v", err)
		}
		<-client.serial
		if client.installed.record.Offline == nil || client.installed.record.Offline.JWS == nil || *client.installed.record.Offline.JWS != string(first) || client.installed.record.Offline.Sequence != 1 {
			t.Fatal("cancelled queued import changed active offline authority")
		}
	})

	t.Run("logout", func(t *testing.T) {
		generation, err := client.generation()
		if err != nil {
			t.Fatal(err)
		}
		client.serial <- struct{}{}
		result := make(chan error, 1)
		go func() {
			_, err := client.importOfflineFileWithGeneration(context.Background(), file, generation)
			result <- err
		}()
		if err := client.Logout(); err != nil {
			<-client.serial
			t.Fatal(err)
		}
		<-client.serial
		if err := <-result; !errors.Is(err, ErrStaleResponse) {
			t.Fatalf("queued import after logout: %v", err)
		}
		if client.installed.record.Offline == nil || client.installed.record.Offline.JWS != nil || client.installed.record.Offline.Sequence != 1 || client.state.offline == nil || client.state.offline.authorized {
			t.Fatal("queued import restored authority after logout")
		}
	})
	if requests.Load() != 0 {
		t.Fatalf("queued offline guards made %d HTTP requests", requests.Load())
	}
	_ = client.Close()
}

func TestInstalledOfflineTamperAfterRestartDoesNotResetIdentity(t *testing.T) {
	key, jwks := offlineFixture(t)
	path := filepath.Join(installedTestTempDir(t), "offline-tamper")
	var requests atomic.Int32
	client := openOfflineFixture(t, path, jwks, &requests)
	token := signOfflineFixture(t, key, client.device.InstallationID, 1, "offline_tamper_issue", time.Now().Unix()+86400)
	if _, err := client.ImportOfflineFile(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	identity := client.device.InstallationID
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	scope := client.installed.record.Scope
	withInstalledFixtureFiles(t, path, scope, func(files installedFiles) {
		data, err := files.read()
		if err != nil {
			t.Fatal(err)
		}
		var record map[string]any
		if err = json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		record["offline"].(map[string]any)["jws"] = "a.b.c"
		corrupted, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err = files.write(corrupted); err != nil {
			t.Fatal(err)
		}
	})
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		return testResponse(request, 503, `{}`), nil
	})
	if _, err := openInstalled(context.Background(), testAppKey(), Options{StatePath: path, BindingMode: BindingDisabled, OfflineKeys: jwks}, transport); !errors.Is(err, ErrStorage) {
		t.Fatalf("tampered saved file reopened: %v", err)
	}
	withInstalledFixtureFiles(t, path, scope, func(files installedFiles) {
		data, err := files.read()
		if err != nil {
			t.Fatal(err)
		}
		var record map[string]any
		if err = json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		if got := record["installation"].(map[string]any)["id"].(string); got != identity {
			t.Fatalf("tampered state recreated installation identity: got %q want %q", got, identity)
		}
	})
	if requests.Load() != 0 {
		t.Fatalf("tampered restart made %d HTTP requests", requests.Load())
	}
}

func TestInstalledOfflineDurableWriteFailureNeverExposesAuthority(t *testing.T) {
	key, jwks := offlineFixture(t)
	path := filepath.Join(installedTestTempDir(t), "offline-write-failure")
	var requests atomic.Int32
	client := openOfflineFixture(t, path, jwks, &requests)
	token := signOfflineFixture(t, key, client.device.InstallationID, 1, "offline_write_issue", time.Now().Unix()+86400)
	client.installed.mu.Lock()
	client.installed.files = offlineFailingInstalledFiles{client.installed.files}
	client.installed.mu.Unlock()
	if _, err := client.ImportOfflineFile(context.Background(), token); !errors.Is(err, ErrStorage) {
		t.Fatalf("failed durable import: %v", err)
	}
	if _, err := client.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrStorage) {
		t.Fatalf("failed write exposed online/offline authority: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("durable write failure made %d HTTP requests", requests.Load())
	}
	_ = client.Close()
	client = openOfflineFixture(t, path, jwks, &requests)
	if client.installed.record.Offline != nil {
		t.Fatal("failed import created persisted offline authority")
	}
	if _, err := client.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("restart restored failed import: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("failed import restart made %d HTTP requests", requests.Load())
	}
	_ = client.Close()
}

func TestInstalledOfflineReplacedLeaseDeniesGuardWithoutWritingState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows keeps the lease file open without delete sharing")
	}
	key, jwks := offlineFixture(t)
	path := filepath.Join(installedTestTempDir(t), "offline-replaced-lease")
	var requests atomic.Int32
	client := openOfflineFixture(t, path, jwks, &requests)
	token := signOfflineFixture(t, key, client.device.InstallationID, 1, "offline_lease_issue", time.Now().Unix()+86400)
	if _, err := client.ImportOfflineFile(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(path, "orbit-storage.bin")
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	leasePath := filepath.Join(path, storageLockName)
	if err = os.Rename(leasePath, leasePath+".replaced"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(leasePath, []byte{1}, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(leasePath, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = client.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrStorage) {
		t.Fatalf("replaced lease allowed offline access: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("replaced-lease guard made %d HTTP requests", requests.Load())
	}
	_ = client.Close()
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("replaced lease caused a write through the untrusted path")
	}
}

func TestInstalledOfflineMachineIdentityChangeRotatesInstallation(t *testing.T) {
	key, jwks := offlineFixture(t)
	path := filepath.Join(installedTestTempDir(t), "offline-binding-change")
	var requests atomic.Int32
	client := openOfflineFixture(t, path, jwks, &requests)
	oldID := client.device.InstallationID
	file := signOfflineFixture(t, key, oldID, 1, "offline_old_machine_issue", time.Now().Unix()+86400)
	if _, err := client.ImportOfflineFile(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		return testResponse(request, 503, `{}`), nil
	})
	changed, err := openInstalled(context.Background(), testAppKey(), Options{
		StatePath: path, BindingMode: BindingCustom,
		Fingerprint: strings.Repeat("a", 64), FingerprintProvider: "custom:offline-test",
		OfflineKeys: jwks,
	}, transport)
	if err != nil {
		t.Fatal(err)
	}
	if changed.device.InstallationID == oldID || changed.state.offline != nil {
		t.Fatal("identity change retained the old installation or offline authority")
	}
	if _, err = changed.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("identity change restored old offline access: %v", err)
	}
	if _, err = changed.ImportOfflineFile(context.Background(), file); err == nil {
		t.Fatal("old installation's signed file was accepted after identity change")
	}
	if requests.Load() != 0 {
		t.Fatalf("identity change made %d HTTP requests", requests.Load())
	}
	_ = changed.Close()
}
