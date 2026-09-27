package orbit

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type delayedVersionStorage struct {
	Storage
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (s *delayedVersionStorage) Version() (uint64, error) {
	if s.calls.Add(1) == 2 {
		close(s.entered)
		<-s.release
	}
	return s.Storage.Version()
}

func TestFloatingActivationIsDurableBeforeSeatAndWarmGuardsAreLocal(t *testing.T) {
	f := newFloatingFixture(t)
	path := filepath.Join(installedTestTempDir(t), "state")
	f.stateDirectory = path
	c, err := f.open(path)
	if err != nil {
		t.Fatal(err)
	}
	activated, err := c.Activate(context.Background(), "synthetic-key")
	if err != nil || activated.Access != AccessOnline || activated.Session == nil || activated.Session.Sequence() != 1 {
		_, credential, _ := c.storage.Load()
		t.Fatalf("floating activation: %+v, %v (starts=%d credential=%v)", activated, err, f.sessionStarts.Load(), credential != nil)
	}
	if f.sessionStarts.Load() != 1 {
		t.Fatalf("session starts=%d, want 1", f.sessionStarts.Load())
	}
	c.installed.mu.Lock()
	state, err := c.installed.files.read()
	c.installed.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(state), strings.Repeat("c", 43)) {
		t.Fatal("activation credential was not persisted")
	}
	if strings.Contains(string(state), activated.Session.ID()) || strings.Contains(string(state), "orbit-session+jwt") {
		t.Fatal("session identifier or grant was persisted")
	}

	current, err := c.StartSession(context.Background())
	if err != nil || current.Session == nil || current.Session.ID() != activated.Session.ID() {
		t.Fatalf("idempotent local start: %+v, %v", current, err)
	}
	for range 5 {
		if _, err := c.RequireAccess(context.Background(), "export"); err != nil {
			t.Fatalf("warm access: %v", err)
		}
	}
	if f.sessionStarts.Load() != 1 || f.validation.Load() != 0 {
		t.Fatalf("warm guard contacted service: starts=%d validations=%d", f.sessionStarts.Load(), f.validation.Load())
	}

	if err := c.EndSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrSessionRequired) {
		t.Fatalf("explicitly ended session authorized work: %v", err)
	}
	resumed, err := c.StartSession(context.Background())
	if err != nil || resumed.Session == nil || resumed.Session.ID() == activated.Session.ID() {
		t.Fatalf("explicit resume did not create a fresh session: %+v, %v", resumed, err)
	}
	if f.sessionStarts.Load() != 2 || f.sessionEnds.Load() != 1 {
		t.Fatalf("starts=%d ends=%d, want 2 and 1", f.sessionStarts.Load(), f.sessionEnds.Load())
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if f.sessionEnds.Load() != 2 {
		t.Fatalf("close did not release the active seat: %d ends", f.sessionEnds.Load())
	}
	reopened, err := f.open(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := reopened.Snapshot()
	if err != nil || restarted.Session == nil || restarted.Session.ID() == resumed.Session.ID() {
		t.Fatalf("restart did not acquire a fresh in-memory session: %+v, %v", restarted, err)
	}
	if f.sessionStarts.Load() != 3 {
		t.Fatalf("restart starts=%d, want 3 total", f.sessionStarts.Load())
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	if f.sessionEnds.Load() != 3 {
		t.Fatalf("restart close did not release the new seat: %d ends", f.sessionEnds.Load())
	}
}

func TestFloatingSeatDenialKeepsCredentialAndNeverPromptsAgain(t *testing.T) {
	f := newFloatingFixture(t)
	f.sessionCapacityDenied.Store(true)
	path := filepath.Join(installedTestTempDir(t), "state")
	c, err := f.open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Activate(context.Background(), "synthetic-key")
	var denied *Error
	if !errors.As(err, &denied) || denied.Code != "concurrent_session_limit_reached" {
		t.Fatalf("seat denial: %v", err)
	}
	version, saved, err := c.storage.Load()
	if err != nil || saved == nil || saved.Credential == "" {
		t.Fatalf("credential was lost after seat denial: %v", err)
	}
	prompted := false
	_, ensureErr := c.EnsureAccess(context.Background(), "export", func(context.Context) (string, error) {
		prompted = true
		return "unexpected", nil
	})
	if !errors.As(ensureErr, &denied) || denied.Code != "concurrent_session_limit_reached" || prompted {
		t.Fatalf("seat denial triggered key prompt: err=%v prompted=%v", ensureErr, prompted)
	}
	afterVersion, after, err := c.storage.Load()
	if err != nil || afterVersion != version || after == nil || after.Credential != saved.Credential {
		t.Fatal("seat denial changed the durable activation credential")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOrdinaryStartAndEndSessionAreLocalNoOpsAfterPolicyCheck(t *testing.T) {
	f := newInstalledFixture(t, false)
	path := filepath.Join(installedTestTempDir(t), "state")
	c, err := f.open(path)
	if err != nil {
		t.Fatal(err)
	}
	mustInstalledActivate(t, c)
	validations := f.validation.Load()
	started, err := c.StartSession(context.Background())
	if err != nil || started.Access != AccessOnline || started.Session != nil {
		t.Fatalf("ordinary start changed access: %+v, %v", started, err)
	}
	if err := c.EndSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.validation.Load() != validations || f.sessionStarts.Load() != 0 || f.sessionEnds.Load() != 0 {
		t.Fatal("known ordinary licence caused a session request or revalidation")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFloatingRenewalRetriesSameSequenceAndDenialClearsAuthority(t *testing.T) {
	f := newFloatingFixture(t)
	path := filepath.Join(installedTestTempDir(t), "state")
	c, err := f.open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	activated, err := c.Activate(context.Background(), "synthetic-key")
	if err != nil || activated.Session == nil {
		t.Fatalf("activation: %+v, %v", activated, err)
	}
	validated, err := c.Refresh(context.Background())
	if err != nil || validated.Session == nil || validated.Session.ID() != activated.Session.ID() || f.sessionStarts.Load() != 1 {
		t.Fatalf("floating validation discarded a live session: %+v, %v (starts=%d)", validated, err, f.sessionStarts.Load())
	}
	generation, err := c.generation()
	if err != nil {
		t.Fatal(err)
	}
	before := activated.Session
	f.sessionRenewTransient.Store(true)
	if _, err := c.renewSession(context.Background(), generation); !errors.Is(err, ErrTransient) {
		t.Fatalf("first renewal: %v", err)
	}
	current, err := c.Snapshot()
	if err != nil || current.Access != AccessOnline || current.Session == nil || current.Session.Sequence() != before.Sequence() {
		t.Fatalf("transient renewal did not retain the exact interval: %+v, %v", current, err)
	}
	f.sessionRenewTransient.Store(false)
	renewed, err := c.renewSession(context.Background(), generation)
	if err != nil || renewed.Session == nil || renewed.Session.Sequence() != 2 {
		t.Fatalf("retry renewal: %+v, %v", renewed, err)
	}
	f.mu.Lock()
	sequences := append([]int64(nil), f.sessionRenewSequence...)
	ids := append([]string(nil), f.sessionRenewIDs...)
	f.mu.Unlock()
	if len(sequences) < 3 || len(ids) != len(sequences) {
		t.Fatalf("expected a transient request, its retry, and the next renewal: sequences=%v ids=%v", sequences, ids)
	}
	for index, sequence := range sequences {
		if sequence != 2 || ids[index] != activated.Session.ID() {
			t.Fatalf("renewal retry changed its session id or sequence: sequences=%v ids=%v", sequences, ids)
		}
	}

	f.sessionRenewDenied.Store(true)
	if _, err := c.renewSession(context.Background(), generation); err == nil {
		t.Fatal("authoritative renewal denial succeeded")
	}
	if _, err := c.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrSessionRequired) {
		t.Fatalf("denied renewal retained authority or reacquired automatically: %v", err)
	}
	if f.sessionStarts.Load() != 1 {
		t.Fatalf("denied renewal unexpectedly acquired another session: %d starts", f.sessionStarts.Load())
	}
}

func TestFloatingLateRenewalCannotRestoreAccessAfterLogout(t *testing.T) {
	f := newFloatingFixture(t)
	path := filepath.Join(installedTestTempDir(t), "state")
	c, err := f.open(path)
	if err != nil {
		t.Fatal(err)
	}
	activated, err := c.Activate(context.Background(), "synthetic-key")
	if err != nil || activated.Session == nil {
		t.Fatalf("activation: %+v, %v", activated, err)
	}
	generation, err := c.generation()
	if err != nil {
		t.Fatal(err)
	}
	f.sessionRenewEntered = make(chan struct{})
	f.sessionRenewRelease = make(chan struct{})
	renewed := make(chan error, 1)
	go func() {
		_, renewErr := c.renewSession(context.Background(), generation)
		renewed <- renewErr
	}()
	select {
	case <-f.sessionRenewEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("renewal request did not reach the fixture")
	}
	if err := c.Logout(); err != nil {
		t.Fatal(err)
	}
	close(f.sessionRenewRelease)
	select {
	case err := <-renewed:
		if !errors.Is(err, ErrStaleResponse) {
			t.Fatalf("late renewal result: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late renewal did not settle")
	}
	snapshot, err := c.Snapshot()
	if err != nil || snapshot.Access != AccessDenied || snapshot.Session != nil {
		t.Fatalf("logout authority was restored: %+v, %v", snapshot, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownFloatingPolicyEndChecksWithoutAcquiring(t *testing.T) {
	f := newFloatingFixture(t)
	path := filepath.Join(installedTestTempDir(t), "state")
	c, err := f.open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Activate(context.Background(), "synthetic-key"); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.state.sessionPolicyKnown = false
	c.state.session = nil
	c.state.sessionDisabled = false
	c.mu.Unlock()
	starts, validations := f.sessionStarts.Load(), f.validation.Load()
	if err := c.EndSession(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.validation.Load() != validations+1 || f.sessionStarts.Load() != starts || !c.state.sessionDisabled {
		t.Fatalf("unknown-policy end acquired a seat: validations %d->%d, starts %d->%d", validations, f.validation.Load(), starts, f.sessionStarts.Load())
	}
	if _, err := c.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrSessionRequired) {
		t.Fatalf("end did not disable automatic reacquisition: %v", err)
	}
}

func TestEnsureAccessUsesFreshActivationSnapshot(t *testing.T) {
	f := newFloatingFixture(t)
	path := filepath.Join(installedTestTempDir(t), "state")
	c, err := f.open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	snapshot, err := c.EnsureAccess(context.Background(), "export", func(context.Context) (string, error) {
		return "synthetic-key", nil
	})
	if err != nil || snapshot.Access != AccessOnline || snapshot.Session == nil {
		t.Fatalf("ensure access: %+v, %v", snapshot, err)
	}
	if f.validation.Load() != 0 || f.activation.Load() != 1 || f.sessionStarts.Load() != 1 {
		t.Fatalf("ensure_access repeated its guard: validations=%d activations=%d starts=%d", f.validation.Load(), f.activation.Load(), f.sessionStarts.Load())
	}
}

func TestFloatingWarmGuardResamplesExpiryAndHonorsCancellation(t *testing.T) {
	f := newFloatingFixture(t)
	path := filepath.Join(installedTestTempDir(t), "state")
	c, err := f.open(path)
	if err != nil {
		t.Fatal(err)
	}
	activated, err := c.Activate(context.Background(), "synthetic-key")
	if err != nil || activated.Session == nil {
		t.Fatalf("activation: %+v, %v", activated, err)
	}
	c.lifecycle.cancel()
	<-c.lifecycle.done
	// Stop only the worker for deterministic clock sampling; keep a fresh
	// client lifetime so the access check does not exercise Close cancellation.
	c.lifecycle.context, c.lifecycle.cancel = context.WithCancel(context.Background())
	c.mu.Lock()
	c.state.session.grant.ExpiresAt = time.Now().Unix() + 1
	c.storage = &delayedVersionStorage{Storage: c.storage, entered: make(chan struct{}), release: make(chan struct{})}
	storage := c.storage.(*delayedVersionStorage)
	c.mu.Unlock()
	result := make(chan error, 1)
	go func() {
		_, guardErr := c.RequireAccess(context.Background(), "export")
		result <- guardErr
	}()
	select {
	case <-storage.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("guard did not reach its final checked snapshot")
	}
	time.Sleep(1200 * time.Millisecond)
	close(storage.release)
	select {
	case guardErr := <-result:
		if !errors.Is(guardErr, ErrSessionRequired) {
			t.Fatalf("warm guard returned access after the signed interval expired: %v", guardErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("warm guard did not finish")
	}
	if f.sessionStarts.Load() != 1 {
		t.Fatalf("expired warm grant triggered acquisition instead of denial: %d starts", f.sessionStarts.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.RequireAccess(ctx, "export"); !errors.Is(err, ErrCancelled) {
		t.Fatalf("cancelled warm guard was accepted: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFloatingBlockedStartAndRenewAreFencedByEnd(t *testing.T) {
	for _, start := range []bool{false, true} {
		t.Run(map[bool]string{true: "start", false: "renew"}[start], func(t *testing.T) {
			f := newFloatingFixture(t)
			c, err := f.open(filepath.Join(installedTestTempDir(t), "state"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if _, err := c.Activate(context.Background(), "synthetic-key"); err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			if start {
				if err := c.EndSession(context.Background()); err != nil {
					t.Fatal(err)
				}
				f.sessionStartEntered = entered
				f.sessionStartRelease = release
			} else {
				f.sessionRenewEntered = entered
				f.sessionRenewRelease = release
			}
			generation, _ := c.generation()
			done := make(chan error, 1)
			go func() {
				var err error
				if start {
					_, err = c.StartSession(context.Background())
				} else {
					_, err = c.renewSession(context.Background(), generation)
				}
				done <- err
			}()
			<-entered
			ended := make(chan error, 1)
			go func() { ended <- c.EndSession(context.Background()) }()
			select {
			case err := <-ended:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				close(release)
				t.Fatal("end waited for blocked network request")
			}
			if _, err := c.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrSessionRequired) {
				t.Fatalf("end retained access: %v", err)
			}
			close(release)
			if err := <-done; !errors.Is(err, ErrStaleResponse) {
				t.Fatalf("late response: %v", err)
			}
			state, err := c.Snapshot()
			if err != nil || state.Access == AccessOnline {
				t.Fatalf("late authority: %+v %v", state, err)
			}
		})
	}
}

func TestFloatingCloseImmediatelyDeniesWarmGuardDuringBlockedRenewal(t *testing.T) {
	f := newFloatingFixture(t)
	c, err := f.open(filepath.Join(installedTestTempDir(t), "state"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Activate(context.Background(), "synthetic-key"); err != nil {
		t.Fatal(err)
	}
	f.sessionRenewEntered = make(chan struct{})
	f.sessionRenewRelease = make(chan struct{})
	generation, _ := c.generation()
	renewed := make(chan error, 1)
	go func() { _, err := c.renewSession(context.Background(), generation); renewed <- err }()
	<-f.sessionRenewEntered
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	<-c.lifecycle.context.Done()
	if _, err := c.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrCancelled) {
		t.Fatalf("closing client retained access: %v", err)
	}
	close(f.sessionRenewRelease)
	if err := <-renewed; !errors.Is(err, ErrCancelled) {
		t.Fatalf("late renewal after close: %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestEndDuringInitialActivationPreservesEndIntent(t *testing.T) {
	for _, account := range []bool{false, true} {
		name := "key"
		if account {
			name = "account"
		}
		t.Run(name, func(t *testing.T) {
			f := newFloatingFixture(t)
			c, err := f.open(filepath.Join(installedTestTempDir(t), "state"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if account {
				if _, err := c.Login(context.Background(), "alice", "synthetic-password"); err != nil {
					t.Fatal(err)
				}
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var blocked atomic.Bool
			c.transport = testTransport(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == clientPrefix+"activations" && !blocked.Swap(true) {
					close(entered)
					<-release
				}
				return f.respond(r)
			})
			done := make(chan error, 1)
			go func() {
				var err error
				if account {
					_, err = c.ActivateAccount(context.Background(), "licence")
				} else {
					_, err = c.Activate(context.Background(), "synthetic-key")
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("activation did not start")
			}
			if err := c.EndSession(context.Background()); err != nil {
				t.Fatal(err)
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			snapshot, err := c.Snapshot()
			if err != nil || snapshot.Access == AccessOnline || snapshot.Session != nil || f.sessionStarts.Load() != 0 {
				t.Fatalf("late activation ignored end: %+v, %v, starts=%d", snapshot, err, f.sessionStarts.Load())
			}
			_, saved, err := c.storage.Load()
			if err != nil || saved == nil {
				t.Fatalf("activation credential lost: %v", err)
			}
			if snapshot, err = c.StartSession(context.Background()); err != nil || snapshot.Access != AccessOnline {
				t.Fatalf("explicit start failed: %+v, %v", snapshot, err)
			}
			if err := c.EndSession(context.Background()); err != nil {
				t.Fatal(err)
			}
			if snapshot, err = c.Activate(context.Background(), "replacement-key"); err != nil || snapshot.Access != AccessOnline {
				t.Fatalf("explicit activation did not restart: %+v, %v", snapshot, err)
			}
		})
	}
}
