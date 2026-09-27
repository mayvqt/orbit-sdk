package orbit

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

type Access string

const (
	AccessDenied          Access = "Denied"
	AccessOnline          Access = "Online"
	AccessOffline         Access = "Offline"
	AccessRefreshRequired Access = "RefreshRequired"
	AccessExpired         Access = "Expired"
)

type StorageCapability string

const (
	StorageMemoryOnly               StorageCapability = "memory_only"
	StoragePrivateFile              StorageCapability = "private_file"
	StorageOperatingSystemProtected StorageCapability = "operating_system_protected"
	StorageCallerProtected          StorageCapability = "caller_provided_protected"
)

// Snapshot is safe display metadata, not reusable authorization. An absent
// entitlement always denies that feature.
type Snapshot struct {
	Access                   Access
	Entitlements             map[string]bool
	ExpiresAt                *time.Time
	NextCheckAt              *time.Time
	CredentialExpiresAt      *time.Time
	ReauthenticationRequired bool
	OfflineAllowed           bool
	OfflineFileMode          bool
	RemainingOffline         time.Duration
	StorageCapability        StorageCapability
	Session                  *SessionMetadata
	// UpdateAvailable is a newer application version reported by the last
	// online check, or empty when the licence policy offers none.
	UpdateAvailable string
}

// HasFeature reports whether the snapshot's current access includes feature.
func (s Snapshot) HasFeature(feature string) bool { return s.Entitlements[feature] }

type accessState struct {
	generation              uint64
	storageVersion          uint64
	account                 *accountSession
	credential              *StoredCredential
	claims                  *grantClaims
	anchor                  *timeAnchor
	transient               bool
	nextRetry               int64
	retryAt                 time.Time // Monotonic pacing only; never grants access.
	failure                 error     // Last validation failure while a retry is paced.
	offline                 *offlineRuntime
	sessionRequired         bool
	sessionPolicyKnown      bool
	sessionDisabled         bool
	session                 *sessionRuntime
	pendingSessionID        string
	pendingSessionSince     time.Time
	sessionRetryAt          time.Time
	sessionLicenceExpiresAt *int64
	updateAvailable         string
	// versionDenial keeps an app_version_unsupported answer while retries are paced.
	versionDenial error
}

// Client is safe for concurrent use. Create a separate context for each selected
// principal/licence. Do not copy a Client after use; share its pointer.
type Client struct {
	key               AppKey
	device            Device
	transport         *Transport
	storage           Storage
	storageCapability StorageCapability
	mu                sync.Mutex
	state             accessState
	serial            chan struct{}
	installed         *installedStorage
	lifecycle         *installedLifecycle
	closed            bool
	keys              grantKeys // Accessed only while holding the serial operation gate.
	offlineKeys       grantKeys
	sessionKeys       sessionVerifierKeys
	appVersion        string
}

func (*Client) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("[Orbit client]")) }

func NewClient(key AppKey, device Device, transport *Transport) (*Client, error) {
	return NewClientWithStorage(key, device, transport, &MemoryStorage{})
}

func NewClientWithStorage(key AppKey, device Device, transport *Transport, storage Storage) (*Client, error) {
	return newClientWithStorage(key, device, transport, storage, false)
}

func newClientWithStorage(key AppKey, device Device, transport *Transport, storage Storage, allowFingerprintChange bool) (*Client, error) {
	if !opaque(key.applicationID) || !opaque(key.environmentID) || key.issuer == "" || !opaque(device.InstallationID) || len(device.InstallationID) < 16 || (device.Fingerprint == nil) != (device.FingerprintProvider == nil) || device.Fingerprint != nil && !lowerHex(*device.Fingerprint, 64) || device.FingerprintProvider != nil && !validProvider(*device.FingerprintProvider) || transport == nil || transport.base == nil || storage == nil || key.apiOrigin != transport.base.Scheme+"://"+transport.base.Host {
		return nil, ErrConfiguration
	}
	if _, err := elapsedClock(); err != nil {
		return nil, err
	}
	version, credential, err := storage.Load()
	if err != nil {
		return nil, ErrStorage
	}
	if credential != nil && (credential.ApplicationID != key.applicationID || credential.EnvironmentID != key.environmentID || credential.InstallationID != device.InstallationID || !allowFingerprintChange && (!equalString(credential.Fingerprint, device.Fingerprint) || !equalString(credential.FingerprintProvider, device.FingerprintProvider)) || !opaque(credential.ActivationID) || !opaque(credential.LicenceID) || !bearer(credential.Credential)) {
		return nil, ErrStorage
	}
	device.Fingerprint = cloneString(device.Fingerprint)
	device.FingerprintProvider = cloneString(device.FingerprintProvider)
	capability := StorageCallerProtected
	if _, ok := storage.(*MemoryStorage); ok {
		capability = StorageMemoryOnly
	}
	return &Client{key: key, device: device, transport: transport, storage: storage, storageCapability: capability, state: accessState{storageVersion: version, credential: cloneCredential(credential)}, serial: make(chan struct{}, 1), keys: make(grantKeys)}, nil
}

func (c *Client) lockOperation(ctx context.Context, generation uint64) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	select {
	case <-ctx.Done():
		return ErrCancelled
	case c.serial <- struct{}{}:
	}
	if ctx.Err() != nil {
		c.unlockOperation()
		return ErrCancelled
	}
	if err := c.checkGeneration(generation); err != nil {
		c.unlockOperation()
		return err
	}
	return nil
}
func (c *Client) unlockOperation() { <-c.serial }
func clearAccess(state *accessState) {
	state.generation++
	state.credential = nil
	state.claims = nil
	state.anchor = nil
	state.transient = false
	state.nextRetry = 0
	state.retryAt = time.Time{}
	state.failure = nil
	state.sessionRequired = false
	state.sessionPolicyKnown = false
	state.sessionDisabled = false
	state.session = nil
	state.pendingSessionID = ""
	state.sessionRetryAt = time.Time{}
	state.sessionLicenceExpiresAt = nil
	state.updateAvailable = ""
	state.versionDenial = nil
	if state.offline != nil {
		state.offline.authorized = false
	}
}
func clearState(state *accessState) { clearAccess(state); state.account = nil }
func (c *Client) syncStorageLocked() error {
	if c.closed || c.lifecycle != nil && c.lifecycle.context.Err() != nil {
		return errClosed
	}
	version, err := c.storage.Version()
	if err != nil {
		clearState(&c.state)
		return ErrStorage
	}
	if version != c.state.storageVersion {
		clearState(&c.state)
		c.state.storageVersion = version
	}
	return nil
}
func (c *Client) invalidateLocked() error {
	version, err := c.storage.Invalidate()
	if err != nil {
		return ErrStorage
	}
	c.state.storageVersion = version
	c.wakeInstalled()
	return nil
}
func (c *Client) invalidateLockedPreservingPending() error {
	if c.installed == nil {
		return c.invalidateLocked()
	}
	version, err := c.installed.invalidatePreservingPending()
	if err != nil {
		return ErrStorage
	}
	c.state.storageVersion = version
	c.wakeInstalled()
	return nil
}
func (c *Client) generation() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.syncStorageLocked(); err != nil {
		return 0, err
	}
	return c.state.generation, nil
}
func (c *Client) checkGeneration(generation uint64) error {
	current, err := c.generation()
	if err != nil {
		return err
	}
	if current != generation {
		return ErrStaleResponse
	}
	return nil
}

// Snapshot checks cross-context invalidation and suspend-aware time every call.
// It never makes a network request and never authorizes a protected operation.
func (c *Client) Snapshot() (Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkedSnapshotLocked()
}

// checkedSnapshotLocked synchronizes external storage and samples the native
// clock once for this decision. A bad sample discards cached authority before
// returning a snapshot that requires online refresh.
func (c *Client) checkedSnapshotLocked() (Snapshot, error) {
	if err := c.syncStorageLocked(); err != nil {
		return Snapshot{}, err
	}
	if c.state.offline != nil && c.state.offline.authorized {
		offline := c.state.offline
		now, wall, err := offlineAnchorNow(offline.anchor)
		if err != nil {
			offline.uncertain = true
			return c.offlineSnapshotLocked(offline, 0, false), nil
		}
		if wall+30 < offline.wallHighWater {
			offline.uncertain = true
			return c.offlineSnapshotLocked(offline, 0, false), nil
		}
		offline.uncertain = false
		return c.offlineSnapshotLocked(offline, now, true), nil
	}
	if c.state.sessionRequired {
		return c.sessionSnapshotLocked(), nil
	}
	if c.state.anchor != nil {
		now, err := c.state.anchor.now()
		if err != nil {
			c.state.claims = nil
			c.state.anchor = nil
			c.state.generation++
			if c.installed != nil {
				if err := c.installed.dropCache(); err != nil {
					return Snapshot{}, err
				}
			}
			return c.snapshotLockedAt(0, false), nil
		}
		return c.snapshotLockedAt(now, true), nil
	}
	return c.snapshotLockedAt(0, false), nil
}
func (c *Client) snapshotLocked() Snapshot {
	if c.state.offline != nil && c.state.offline.authorized {
		offline := c.state.offline
		now, wall, err := offlineAnchorNow(offline.anchor)
		if err != nil {
			offline.uncertain = true
			return c.offlineSnapshotLocked(offline, 0, false)
		}
		if wall+30 < offline.wallHighWater {
			offline.uncertain = true
			return c.offlineSnapshotLocked(offline, 0, false)
		}
		offline.uncertain = false
		return c.offlineSnapshotLocked(offline, now, true)
	}
	if c.state.sessionRequired {
		return c.sessionSnapshotLocked()
	}
	if c.state.anchor == nil {
		return c.snapshotLockedAt(0, false)
	}
	now, err := c.state.anchor.now()
	return c.snapshotLockedAt(now, err == nil)
}
func (c *Client) offlineSnapshotLocked(offline *offlineRuntime, now int64, clockValid bool) Snapshot {
	snapshot := Snapshot{Access: AccessDenied, Entitlements: map[string]bool{}, OfflineAllowed: true, OfflineFileMode: true, StorageCapability: c.storageCapability}
	expires := time.Unix(offline.claims.ExpiresAt, 0).UTC()
	snapshot.ExpiresAt = &expires
	if !clockValid {
		return snapshot
	}
	if now >= offline.claims.ExpiresAt {
		snapshot.Access = AccessExpired
		return snapshot
	}
	snapshot.Access = AccessOffline
	snapshot.Entitlements = make(map[string]bool, len(offline.claims.Entitlements))
	for name, enabled := range offline.claims.Entitlements {
		snapshot.Entitlements[name] = enabled
	}
	snapshot.RemainingOffline = time.Duration(offline.claims.ExpiresAt-now) * time.Second
	return snapshot
}
func (c *Client) snapshotLockedAt(now int64, clockValid bool) Snapshot {
	snapshot := Snapshot{Access: AccessDenied, Entitlements: make(map[string]bool), ReauthenticationRequired: true, StorageCapability: c.storageCapability, UpdateAvailable: c.state.updateAvailable}
	state := &c.state
	var credentialExpiry *int64
	if state.credential != nil {
		snapshot.Access = AccessRefreshRequired
		expiry := state.credential.CredentialExpiresAt
		if expiry != 0 {
			credentialExpiry = &expiry
			at := time.Unix(expiry, 0).UTC()
			snapshot.CredentialExpiresAt = &at
		}
		snapshot.ReauthenticationRequired = false
	}
	if state.claims == nil || state.anchor == nil || !clockValid {
		return snapshot
	}
	claims := state.claims
	expiresAt, nextCheckAt := time.Unix(claims.ExpiresAt, 0).UTC(), time.Unix(claims.RefreshAfter, 0).UTC()
	snapshot.ExpiresAt = &expiresAt
	snapshot.NextCheckAt = &nextCheckAt
	snapshot.ReauthenticationRequired = credentialExpiry != nil && *credentialExpiry <= saturatingAdd(now, 86400)
	snapshot.OfflineAllowed = claims.OfflineAllowed
	switch {
	case claims.ExpiresAt <= now:
		snapshot.Access = AccessExpired
	case state.transient:
		if claims.OfflineAllowed {
			snapshot.Access = AccessOffline
		} else {
			snapshot.Access = AccessRefreshRequired
		}
	case claims.RefreshAfter <= now:
		snapshot.Access = AccessRefreshRequired
	default:
		snapshot.Access = AccessOnline
	}
	if snapshot.Access == AccessOnline || snapshot.Access == AccessOffline {
		for name, allowed := range claims.Entitlements {
			snapshot.Entitlements[name] = allowed
		}
		if claims.OfflineAllowed {
			snapshot.RemainingOffline = time.Duration(claims.ExpiresAt-now) * time.Second
		}
	}
	return snapshot
}

// Logout clears local access and customer session immediately and best-effort
// releases any floating seat. It never deactivates the installation.
func (c *Client) Logout() error {
	c.mu.Lock()
	if err := c.syncStorageLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	release, id := cloneCredential(c.state.credential), ""
	if c.state.session != nil {
		id = c.state.session.metadata.id
	} else {
		id = c.state.pendingSessionID
	}
	checkpointErr := c.checkpointOfflineLocked(true)
	clearState(&c.state)
	if err := c.invalidateLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	if release != nil && id != "" {
		c.bestEffortEnd(release, id)
	}
	return checkpointErr
}

func (c *Client) Activate(ctx context.Context, key string, operationID ...string) (Snapshot, error) {
	if len(operationID) > 1 || len(operationID) == 1 && !validOperationID(operationID[0]) {
		return Snapshot{}, ErrConfiguration
	}
	return c.ActivateWithPrevious(ctx, key, "", operationID...)
}
func (c *Client) ActivateWithPrevious(ctx context.Context, key, previousCredential string, operationIDs ...string) (Snapshot, error) {
	if len(operationIDs) > 1 || len(operationIDs) == 1 && !validOperationID(operationIDs[0]) {
		return Snapshot{}, ErrConfiguration
	}
	idempotencyKey := ""
	if len(operationIDs) == 1 {
		idempotencyKey = operationIDs[0]
	}
	return c.activate(ctx, key, "", previousCredential, idempotencyKey)
}
func (c *Client) activate(ctx context.Context, key, licence, previousCredential, idempotencyKey string) (Snapshot, error) {
	ctx, stop := c.operationContext(ctx)
	defer stop()
	if (licence == "" && (key == "" || len(key) > 256)) || (licence != "" && !opaque(licence)) || (idempotencyKey != "" && !validOperationID(idempotencyKey)) || (previousCredential != "" && !bearer(previousCredential)) {
		return Snapshot{}, ErrConfiguration
	}
	if idempotencyKey == "" && c.installed == nil {
		device, err := NewInstallation()
		if err != nil {
			return Snapshot{}, err
		}
		idempotencyKey = device.InstallationID
	}
	generation, err := c.generation()
	if err != nil {
		return Snapshot{}, err
	}
	if err := c.lockOperation(ctx, generation); err != nil {
		return Snapshot{}, err
	}
	defer c.unlockOperation()
	c.mu.Lock()
	if err := c.syncStorageLocked(); err != nil {
		c.mu.Unlock()
		return Snapshot{}, err
	}
	if c.state.generation != generation {
		c.mu.Unlock()
		return Snapshot{}, ErrStaleResponse
	}
	if c.installed != nil {
		if c.state.offline != nil && c.state.offline.authorized {
			if err := c.checkpointOfflineLocked(true); err != nil {
				c.mu.Unlock()
				return Snapshot{}, err
			}
		}
		customerID := ""
		if licence != "" && c.state.account == nil {
			c.mu.Unlock()
			return Snapshot{}, ErrReauthenticationRequired
		}
		if licence != "" {
			customerID = c.state.account.account.Customer.ID
		}
		id, version, err := c.installed.begin(key, licence, customerID, previousCredential, idempotencyKey, c.device.Fingerprint, c.device.FingerprintProvider)
		if err != nil {
			c.mu.Unlock()
			return Snapshot{}, err
		}
		idempotencyKey, c.state.storageVersion = id, version
	}
	body := c.scopeBody(map[string]any{"installation_id": c.device.InstallationID, "fingerprint": c.device.Fingerprint, "fingerprint_provider": c.device.FingerprintProvider, "previous_credential": optionalString(previousCredential), "idempotency_key": idempotencyKey})
	if c.appVersion != "" {
		body["app_version"] = c.appVersion
	}
	if licence == "" {
		clearState(&c.state)
		body["licence_key"] = key
	} else {
		if c.state.account == nil {
			c.mu.Unlock()
			return Snapshot{}, ErrReauthenticationRequired
		}
		body["customer_session"] = c.state.account.token
		body["licence_id"] = licence
		clearAccess(&c.state)
	}
	if c.installed == nil {
		if err := c.invalidateLocked(); err != nil {
			c.mu.Unlock()
			return Snapshot{}, err
		}
	} else {
		body["credential_mode"] = "persistent"
	}
	generation = c.state.generation
	c.mu.Unlock()
	started, err := captureStart()
	if err != nil {
		return Snapshot{}, err
	}
	budget, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	response, responseError := c.transport.Post(budget, clientPrefix+"activations", body, true)
	if budget.Err() != nil && ctx.Err() == nil {
		responseError = ErrTransient
	}
	return c.acceptAndAcquire(ctx, budget, response, responseError, generation, nil, licence, started)
}

// Refresh validates the existing credential without extending its fixed expiry.
func (c *Client) Refresh(ctx context.Context) (Snapshot, error) {
	return c.refresh(ctx, false)
}

func (c *Client) refresh(ctx context.Context, respectRetry bool) (Snapshot, error) {
	return c.refreshMode(ctx, respectRetry, true)
}

func (c *Client) refreshWithoutSessionAcquire(ctx context.Context) (Snapshot, error) {
	return c.refreshMode(ctx, false, false)
}

func (c *Client) refreshMode(ctx context.Context, respectRetry, acquireSession bool) (Snapshot, error) {
	ctx, stop := c.operationContext(ctx)
	defer stop()
	generation, err := c.generation()
	if err != nil {
		return Snapshot{}, err
	}
	if err := c.lockOperation(ctx, generation); err != nil {
		return Snapshot{}, err
	}
	defer c.unlockOperation()
	c.mu.Lock()
	if err := c.syncStorageLocked(); err != nil {
		c.mu.Unlock()
		return Snapshot{}, err
	}
	if c.state.generation != generation {
		c.mu.Unlock()
		return Snapshot{}, ErrStaleResponse
	}
	if respectRetry {
		snapshot := c.snapshotLocked()
		retryDue := !time.Now().Before(c.state.retryAt)
		if c.state.anchor != nil {
			if now, err := c.state.anchor.now(); err == nil {
				retryDue = now >= c.state.nextRetry
			}
		}
		if !retryDue || snapshot.Access != AccessRefreshRequired && snapshot.Access != AccessExpired && snapshot.Access != AccessOffline {
			failure := c.state.failure
			if c.state.transient {
				failure = nil
			}
			c.mu.Unlock()
			if snapshot.Access != AccessOffline && snapshot.Access != AccessOnline && failure != nil {
				return Snapshot{}, failure
			}
			return snapshot, nil
		}
	}
	saved := cloneCredential(c.state.credential)
	c.mu.Unlock()
	if saved == nil {
		return Snapshot{}, ErrReauthenticationRequired
	}
	started, err := captureStart()
	if err != nil {
		return Snapshot{}, err
	}
	budget, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	body := c.credentialBody(saved)
	if c.appVersion != "" {
		body["app_version"] = c.appVersion
	}
	response, responseError := c.transport.Post(budget, clientPrefix+"activations/"+saved.ActivationID+"/validate", body, true)
	if budget.Err() != nil && ctx.Err() == nil {
		responseError = ErrTransient
	}
	if acquireSession {
		return c.acceptAndAcquire(ctx, budget, response, responseError, generation, saved, "", started)
	}
	return c.accept(ctx, budget, response, responseError, generation, saved, "", started)
}
func (c *Client) credentialBody(saved *StoredCredential) map[string]any {
	return c.scopeBody(map[string]any{"credential": saved.Credential, "installation_id": c.device.InstallationID, "fingerprint": c.device.Fingerprint, "fingerprint_provider": c.device.FingerprintProvider})
}

// Deactivate clears activation access before the request while retaining a
// customer login. Only a nil error confirms server-side slot release.
func (c *Client) Deactivate(ctx context.Context, ids ...string) error {
	if len(ids) > 1 || len(ids) == 1 && !validOperationID(ids[0]) {
		return ErrConfiguration
	}
	idempotencyKey := ""
	if len(ids) == 1 {
		idempotencyKey = ids[0]
	}
	if idempotencyKey == "" {
		device, err := NewInstallation()
		if err != nil {
			return err
		}
		idempotencyKey = device.InstallationID
	}
	if !validOperationID(idempotencyKey) {
		return ErrConfiguration
	}
	c.mu.Lock()
	if err := c.syncStorageLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	saved := cloneCredential(c.state.credential)
	checkpointErr := c.checkpointOfflineLocked(true)
	clearAccess(&c.state)
	if err := c.invalidateLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	generation := c.state.generation
	c.mu.Unlock()
	if checkpointErr != nil {
		return checkpointErr
	}
	if saved == nil {
		return ErrReauthenticationRequired
	}
	body := c.credentialBody(saved)
	body["idempotency_key"] = idempotencyKey
	response, err := c.transport.Post(ctx, clientPrefix+"activations/"+saved.ActivationID+"/deactivate", body, true)
	if generationErr := c.checkGeneration(generation); generationErr != nil {
		return generationErr
	}
	if err != nil {
		return err
	}
	if response != nil {
		return ErrInvalidResponse
	}
	return nil
}

// EnsureAccess asks for a key only when access is not activated. It never
// calls the prompt after an outage, feature denial, or another failure.
func (c *Client) EnsureAccess(ctx context.Context, feature string, askForKey func(context.Context) (string, error)) (Snapshot, error) {
	snapshot, err := c.RequireAccess(ctx, feature)
	if !errors.Is(err, ErrNotActivated) {
		return snapshot, err
	}
	if askForKey == nil {
		return Snapshot{}, ErrNotActivated
	}
	key, err := askForKey(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	if strings.TrimSpace(key) == "" {
		return Snapshot{}, ErrNotActivated
	}
	snapshot, err = c.Activate(ctx, key)
	if err != nil {
		return Snapshot{}, err
	}
	if ctx.Err() != nil {
		return Snapshot{}, ErrCancelled
	}
	if snapshot.Access != AccessOnline && snapshot.Access != AccessOffline {
		return Snapshot{}, ErrNotActivated
	}
	if !snapshot.HasFeature(feature) {
		return Snapshot{}, ErrFeatureUnavailable
	}
	return snapshot, nil
}

// RequireAccess refreshes when needed, rechecks invalidation and expiry, and
// permits offline work only within a verified policy grant after an outage.
func (c *Client) RequireAccess(ctx context.Context, feature string) (Snapshot, error) {
	if ctx.Err() != nil {
		return Snapshot{}, ErrCancelled
	}
	c.mu.Lock()
	snapshot, err := c.checkedSnapshotLocked()
	if err != nil {
		c.mu.Unlock()
		return Snapshot{}, err
	}
	if ctx.Err() != nil {
		c.mu.Unlock()
		return Snapshot{}, ErrCancelled
	}
	if snapshot.OfflineFileMode {
		if snapshot.Access == AccessExpired {
			c.mu.Unlock()
			return Snapshot{}, offlineError("offline_file_expired")
		}
		if snapshot.Access != AccessOffline {
			c.mu.Unlock()
			return Snapshot{}, ErrClockUncertain
		}
		if !snapshot.HasFeature(feature) {
			c.mu.Unlock()
			return Snapshot{}, ErrFeatureUnavailable
		}
		c.mu.Unlock()
		return snapshot, nil
	}
	if c.state.sessionRequired {
		if snapshot.Access == AccessOnline {
			if !snapshot.HasFeature(feature) {
				c.mu.Unlock()
				return Snapshot{}, ErrFeatureUnavailable
			}
			final, finalErr := c.checkedSnapshotLocked()
			if finalErr != nil {
				c.mu.Unlock()
				return Snapshot{}, finalErr
			}
			if ctx.Err() != nil {
				c.mu.Unlock()
				return Snapshot{}, ErrCancelled
			}
			if final.Access != AccessOnline {
				c.mu.Unlock()
				return Snapshot{}, ErrSessionRequired
			}
			if !final.HasFeature(feature) {
				c.mu.Unlock()
				return Snapshot{}, ErrFeatureUnavailable
			}
			c.mu.Unlock()
			return final, nil
		}
		if c.state.sessionDisabled {
			c.mu.Unlock()
			return Snapshot{}, ErrSessionRequired
		}
		c.mu.Unlock()
		session, err := c.StartSession(ctx)
		if err != nil {
			return Snapshot{}, err
		}
		if !session.HasFeature(feature) {
			return Snapshot{}, ErrFeatureUnavailable
		}
		return session, nil
	}
	if snapshot.Access == AccessOnline {
		if !snapshot.HasFeature(feature) {
			c.mu.Unlock()
			return Snapshot{}, ErrFeatureUnavailable
		}
		c.mu.Unlock()
		return snapshot, nil
	}
	if snapshot.Access != AccessRefreshRequired && snapshot.Access != AccessExpired && snapshot.Access != AccessOffline {
		err := c.unavailableLocked()
		c.mu.Unlock()
		return Snapshot{}, err
	}
	c.mu.Unlock()
	if _, err := c.refresh(ctx, true); err != nil && !errors.Is(err, ErrTransient) {
		return Snapshot{}, err
	}
	if ctx.Err() != nil {
		return Snapshot{}, ErrCancelled
	}
	// Network completion may race logout or external invalidation. Re-sample
	// current storage and time after refresh before returning authorization.
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot, err = c.checkedSnapshotLocked()
	if err != nil {
		return Snapshot{}, err
	}
	if ctx.Err() != nil {
		return Snapshot{}, ErrCancelled
	}
	if snapshot.Access != AccessOnline && snapshot.Access != AccessOffline {
		return Snapshot{}, c.unavailableLocked()
	}
	if !snapshot.Entitlements[feature] {
		return Snapshot{}, ErrFeatureUnavailable
	}
	return snapshot, nil
}

// unavailableLocked explains why access is unavailable: an unsupported app
// version, the last paced validation failure when a credential remains, an
// outage, otherwise missing activation.
func (c *Client) unavailableLocked() error {
	if c.state.versionDenial != nil {
		return c.state.versionDenial
	}
	if c.state.credential != nil && c.state.failure != nil {
		return c.state.failure
	}
	if c.state.transient {
		return ErrTransient
	}
	return ErrNotActivated
}

func (c *Client) acceptAndAcquire(ctx, budget context.Context, response json.RawMessage, responseError error, generation uint64, previous *StoredCredential, licence string, started requestStart) (Snapshot, error) {
	snapshot, err := c.accept(ctx, budget, response, responseError, generation, previous, licence, started)
	if err != nil {
		return snapshot, err
	}
	c.mu.Lock()
	required, disabled, currentGeneration := c.state.sessionRequired, c.state.sessionDisabled, c.state.generation
	c.mu.Unlock()
	if required && !disabled {
		return c.startSessionSerialized(ctx, currentGeneration, false)
	}
	return snapshot, nil
}

func (c *Client) accept(ctx, budget context.Context, response json.RawMessage, responseError error, generation uint64, previous *StoredCredential, licence string, started requestStart) (Snapshot, error) {
	if err := c.checkGeneration(generation); err != nil {
		return Snapshot{}, err
	}
	var saved *StoredCredential
	var claims *grantClaims
	var anchor *timeAnchor
	floating := false
	err := responseError
	verifying := err == nil
	updateAvailable := ""
	if err == nil {
		updateAvailable, err = updateHint(response)
	}
	if err == nil {
		saved, claims, anchor, floating, err = c.verifyReply(budget, response, previous, licence, started)
	}
	var sessionLicenceExpiry *int64
	if err == nil && floating {
		var reply grantReply
		if decodeJSON(response, &reply) != nil {
			err = ErrInvalidResponse
		} else if reply.LicenceExpiresAt != nil {
			value, parseErr := timestamp(*reply.LicenceExpiresAt)
			if parseErr != nil || value > 253402300799 {
				err = ErrInvalidResponse
			} else {
				sessionLicenceExpiry = &value
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if syncErr := c.syncStorageLocked(); syncErr != nil {
		return Snapshot{}, syncErr
	}
	if c.state.generation != generation {
		return Snapshot{}, ErrStaleResponse
	}
	if ctx.Err() != nil {
		return Snapshot{}, ErrCancelled
	}
	if verifying && errors.Is(err, ErrCancelled) && budget.Err() != nil {
		err = ErrTransient
	}
	if err == nil {
		if budget.Err() != nil {
			err = ErrTransient
		} else {
			var saveErr error
			if c.installed != nil {
				if floating {
					saveErr = c.installed.commitCredential(c.state.storageVersion, saved)
				} else {
					saveErr = c.installed.commit(c.state.storageVersion, saved, response, c.keys, anchor)
				}
			} else {
				saveErr = c.storage.Save(c.state.storageVersion, *saved)
			}
			if err := saveErr; err != nil {
				clearState(&c.state)
				if errors.Is(err, ErrStaleResponse) {
					return Snapshot{}, ErrStaleResponse
				}
				return Snapshot{}, ErrStorage
			}
			c.state.credential = cloneCredential(saved)
			c.state.claims = claims
			c.state.anchor = anchor
			preserveSession := floating && previous != nil && c.state.sessionRequired &&
				previous.ActivationID == saved.ActivationID && previous.LicenceID == saved.LicenceID &&
				previous.InstallationID == saved.InstallationID
			c.state.sessionRequired = floating
			c.state.sessionPolicyKnown = true
			if !preserveSession {
				c.state.session = nil
				c.state.pendingSessionID = ""
				c.state.sessionRetryAt = time.Time{}
			}
			c.state.sessionLicenceExpiresAt = sessionLicenceExpiry
			if !floating {
				c.state.sessionDisabled = false
			}
			c.state.transient = false
			c.state.updateAvailable = updateAvailable
			c.state.versionDenial = nil
			if c.lifecycle != nil {
				c.lifecycle.restoring = false
			}
			c.state.nextRetry = 0
			c.state.retryAt = time.Time{}
			c.state.failure = nil
			c.wakeInstalled()
			return c.snapshotLocked(), nil
		}
	}
	if errors.Is(err, ErrTransient) {
		delaySeconds := retryDelaySeconds()
		if verifying {
			// An unavailable signing key is no evidence for offline fallback.
			// Keep only the existing credential for a fresh validation attempt;
			// never save this unverified reply or its clock anchor.
			c.state.generation++
			c.state.claims = nil
			if c.installed != nil {
				if e := c.installed.dropCache(); e != nil {
					return Snapshot{}, e
				}
			}
		}
		wasTransient := c.state.transient
		c.state.transient = true
		c.state.failure = err
		c.state.nextRetry = delaySeconds
		c.state.retryAt = time.Now().Add(time.Duration(delaySeconds) * time.Second)
		if c.state.anchor != nil {
			if now, clockErr := c.state.anchor.now(); clockErr == nil {
				c.state.nextRetry = saturatingAdd(now, delaySeconds)
			}
		}
		c.wakeInstalled()
		snapshot := c.snapshotLocked()
		if snapshot.Access == AccessOffline {
			if c.installed != nil && (!wasTransient || c.lifecycle.restoring) {
				c.lifecycle.restoring = false
				if e := c.checkpointLocked(true); e != nil {
					return Snapshot{}, e
				}
			}
			return snapshot, nil
		}
		return Snapshot{}, err
	}
	if previous != nil && errors.Is(err, ErrAppVersionUnsupported) {
		// Keep the activation for an updated application, but drop cached access
		// without offline fallback and pace further validation.
		c.state.generation++
		c.state.claims = nil
		c.state.anchor = nil
		c.state.transient = false
		c.state.session = nil
		c.state.pendingSessionID = ""
		c.state.updateAvailable = ""
		c.state.failure = nil
		c.state.versionDenial = err
		c.state.retryAt = time.Now().Add(time.Minute)
		c.state.nextRetry = 0
		if c.installed != nil {
			if e := c.installed.dropCache(); e != nil {
				return Snapshot{}, e
			}
		}
		return Snapshot{}, err
	}
	if errors.Is(err, ErrCancelled) && budget.Err() == nil {
		return Snapshot{}, ErrCancelled
	}
	if errors.Is(err, ErrCancelled) {
		err = ErrInvalidResponse
	}
	if c.installed != nil && !errors.Is(err, ErrDenied) {
		// A malformed reply, TLS failure or clock problem is no evidence that the
		// saved credential or pending activation is invalid. Keep both for a
		// later verified validation, discard cached authority and pace retries.
		credential, account := c.state.credential, c.state.account
		clearState(&c.state)
		c.state.credential, c.state.account = credential, account
		if storageErr := c.installed.dropCache(); storageErr != nil {
			return Snapshot{}, storageErr
		}
		c.state.failure = err
		c.state.retryAt = time.Now().Add(time.Duration(retryDelaySeconds()) * time.Second)
		return Snapshot{}, err
	}
	clearState(&c.state)
	if storageErr := c.invalidateLocked(); storageErr != nil {
		return Snapshot{}, storageErr
	}
	return Snapshot{}, err
}

// retryDelaySeconds paces automatic validation after a failure by 15-44 seconds.
func retryDelaySeconds() int64 {
	var entropy [2]byte
	delaySeconds := int64(15)
	if _, err := rand.Read(entropy[:]); err == nil {
		delaySeconds += int64(uint16(entropy[0])<<8|uint16(entropy[1])) % 30
	}
	return delaySeconds
}

type grantReply struct {
	ActivationID        string  `json:"activation_id"`
	InstallationID      string  `json:"installation_id"`
	Credential          *string `json:"credential"`
	CredentialExpiresAt *string `json:"credential_expires_at"`
	Grant               *string `json:"grant"`
	ServerTime          string  `json:"server_time"`
	BindingMode         string  `json:"binding_mode"`
	FingerprintProvider *string `json:"fingerprint_provider"`
	LicenceExpiresAt    *string `json:"licence_expires_at"`
	SecretReplayExpired bool    `json:"secret_replay_expired"`
	LicenceID           *string `json:"licence_id,omitempty"`
	SessionRequired     *bool   `json:"session_required,omitempty"`
}

func (c *Client) verifyReply(ctx context.Context, data json.RawMessage, previous *StoredCredential, licence string, started requestStart) (*StoredCredential, *grantClaims, *timeAnchor, bool, error) {
	var reply grantReply
	var fields map[string]json.RawMessage
	if decodeJSON(data, &reply) != nil || json.Unmarshal(data, &fields) != nil || fields["credential_expires_at"] == nil {
		return nil, nil, nil, false, ErrInvalidResponse
	}
	if reply.SecretReplayExpired {
		return nil, nil, nil, false, ErrReauthenticationRequired
	}
	if !opaque(reply.ActivationID) || reply.InstallationID != c.device.InstallationID || !equalString(reply.FingerprintProvider, c.device.FingerprintProvider) || (reply.BindingMode != "none" && reply.BindingMode != "hwid") || reply.BindingMode == "hwid" && c.device.Fingerprint == nil {
		return nil, nil, nil, false, ErrInvalidResponse
	}
	floating := false
	if raw, present := fields["session_required"]; present {
		if json.Unmarshal(raw, &floating) != nil || !floating || reply.LicenceID == nil || !opaque(*reply.LicenceID) || reply.Grant != nil || string(fields["grant"]) != "null" {
			return nil, nil, nil, false, ErrInvalidResponse
		}
	} else if reply.LicenceID != nil || reply.Grant == nil || fields["licence_id"] != nil {
		return nil, nil, nil, false, ErrInvalidResponse
	}
	if floating && ((licence != "" && *reply.LicenceID != licence) || (previous != nil && *reply.LicenceID != previous.LicenceID)) {
		return nil, nil, nil, false, ErrInvalidResponse
	}
	server, err := timestamp(reply.ServerTime)
	if err != nil {
		return nil, nil, nil, false, err
	}
	anchor := &timeAnchor{server: server, requestStart: started}
	now, err := anchor.now()
	if err != nil {
		return nil, nil, nil, false, err
	}
	expiry := int64(0)
	if reply.CredentialExpiresAt != nil {
		expiry, err = timestamp(*reply.CredentialExpiresAt)
		if err != nil || expiry <= now || expiry > saturatingAdd(now, 30*86400) {
			return nil, nil, nil, false, ErrInvalidResponse
		}
	}
	if previous == nil && ((c.installed != nil && expiry != 0) || (c.installed == nil && expiry == 0)) {
		return nil, nil, nil, false, ErrInvalidResponse
	}
	if previous != nil && (reply.ActivationID != previous.ActivationID || expiry != previous.CredentialExpiresAt || reply.Credential != nil) {
		return nil, nil, nil, false, ErrInvalidResponse
	}
	if floating {
		credential := ""
		if reply.Credential != nil {
			credential = *reply.Credential
		} else if previous != nil {
			credential = previous.Credential
		}
		if !bearer(credential) {
			return nil, nil, nil, false, ErrInvalidResponse
		}
		return &StoredCredential{ApplicationID: c.key.applicationID, EnvironmentID: c.key.environmentID, ActivationID: reply.ActivationID, LicenceID: *reply.LicenceID, InstallationID: c.device.InstallationID, Credential: credential, CredentialExpiresAt: expiry, Fingerprint: cloneString(c.device.Fingerprint), FingerprintProvider: cloneString(c.device.FingerprintProvider)}, nil, nil, true, nil
	}
	header, _, err := parseHeader(*reply.Grant)
	if err != nil {
		return nil, nil, nil, false, err
	}
	if _, known := c.keys[header.KeyID]; !known {
		data, err := c.transport.Get(ctx, c.accountPath(jwksPath, ""))
		if err != nil {
			return nil, nil, nil, false, err
		}
		keys, err := parseKeys(data)
		if err != nil {
			return nil, nil, nil, false, err
		}
		c.keys = keys
	}
	var licenceExpiry *int64
	if reply.LicenceExpiresAt != nil {
		value, err := timestamp(*reply.LicenceExpiresAt)
		if err != nil {
			return nil, nil, nil, false, err
		}
		licenceExpiry = &value
	}
	now, err = anchor.now()
	if err != nil {
		return nil, nil, nil, false, err
	}
	if licence == "" && previous != nil {
		licence = previous.LicenceID
	}
	claims, err := verifyGrant(*reply.Grant, c.keys, expectedGrant{issuer: c.key.issuer, application: c.key.applicationID, environment: c.key.environmentID, licence: licence, activation: reply.ActivationID, installation: c.device.InstallationID, fingerprint: c.device.Fingerprint, fingerprintProvider: c.device.FingerprintProvider, allowUnboundFingerprint: true, credentialExpiresAt: expiry, credentialPersistent: expiry == 0, licenceExpiresAt: licenceExpiry, now: now})
	if err != nil {
		return nil, nil, nil, false, err
	}
	if claims.BindingMode != reply.BindingMode {
		return nil, nil, nil, false, ErrInvalidResponse
	}
	credential := ""
	if reply.Credential != nil {
		credential = *reply.Credential
	} else if previous != nil {
		credential = previous.Credential
	}
	if !bearer(credential) {
		return nil, nil, nil, false, ErrInvalidResponse
	}
	saved := &StoredCredential{ApplicationID: c.key.applicationID, EnvironmentID: c.key.environmentID, ActivationID: reply.ActivationID, LicenceID: claims.Subject, InstallationID: c.device.InstallationID, Credential: credential, CredentialExpiresAt: expiry, Fingerprint: cloneString(c.device.Fingerprint), FingerprintProvider: cloneString(c.device.FingerprintProvider)}
	return saved, claims, anchor, false, nil
}
func bearer(value string) bool { return len(value) == 43 && asciiToken(value) }
func validOperationID(value string) bool {
	if !utf8.ValidString(value) || len(value) < 16 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
