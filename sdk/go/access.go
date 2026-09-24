package orbit

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Config fixes the public scope and exact deployment issuer for one client.
type Config struct {
	ApplicationID string
	EnvironmentID string
	Issuer        string
}

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
	StorageMemoryOnly      StorageCapability = "memory_only"
	StorageCallerProtected StorageCapability = "caller_provided_protected"
)

// Snapshot is safe display metadata, not reusable authorization. Unix timestamps
// are seconds. An absent entitlement always denies that feature.
type Snapshot struct {
	Access                   Access
	Entitlements             map[string]bool
	ExpiresAt                *int64
	NextCheckAt              *int64
	CredentialExpiresAt      *int64
	ReauthenticationRequired bool
	OfflineAllowed           bool
	RemainingOfflineSeconds  uint64
	StorageCapability        StorageCapability
}
type accessState struct {
	generation     uint64
	storageVersion uint64
	account        *accountSession
	credential     *StoredCredential
	claims         *grantClaims
	anchor         *timeAnchor
	transient      bool
	nextRetry      int64
	retryAt        time.Time // Monotonic pacing only; never grants access.
}

// Client is safe for concurrent use. Create a separate context for each selected
// principal/licence. Do not copy a Client after use; share its pointer.
type Client struct {
	config            Config
	device            Device
	transport         *Transport
	storage           Storage
	storageCapability StorageCapability
	mu                sync.Mutex
	state             accessState
	serial            chan struct{}
	keys              grantKeys // Accessed only while holding the serial operation gate.
}

func (*Client) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("[Orbit client]")) }

func NewClient(config Config, device Device, transport *Transport) (*Client, error) {
	return NewClientWithStorage(config, device, transport, &MemoryStorage{})
}

func NewClientWithStorage(config Config, device Device, transport *Transport, storage Storage) (*Client, error) {
	if !opaque(config.ApplicationID) || !opaque(config.EnvironmentID) || config.Issuer == "" || !opaque(device.InstallationID) || len(device.InstallationID) < 16 || (device.Fingerprint == nil) != (device.FingerprintProvider == nil) || device.Fingerprint != nil && !lowerHex(*device.Fingerprint, 64) || device.FingerprintProvider != nil && !validProvider(*device.FingerprintProvider) || transport == nil || transport.base == nil || storage == nil {
		return nil, ErrConfiguration
	}
	if _, err := elapsedClock(); err != nil {
		return nil, err
	}
	version, credential, err := storage.Load()
	if err != nil {
		return nil, ErrStorage
	}
	if credential != nil && (credential.ApplicationID != config.ApplicationID || credential.EnvironmentID != config.EnvironmentID || credential.InstallationID != device.InstallationID || !equalString(credential.Fingerprint, device.Fingerprint) || !equalString(credential.FingerprintProvider, device.FingerprintProvider) || !opaque(credential.ActivationID) || !opaque(credential.LicenceID) || !bearer(credential.Credential)) {
		return nil, ErrStorage
	}
	device.Fingerprint = cloneString(device.Fingerprint)
	device.FingerprintProvider = cloneString(device.FingerprintProvider)
	capability := StorageCallerProtected
	if _, ok := storage.(*MemoryStorage); ok {
		capability = StorageMemoryOnly
	}
	return &Client{config: config, device: device, transport: transport, storage: storage, storageCapability: capability, state: accessState{storageVersion: version, credential: cloneCredential(credential)}, serial: make(chan struct{}, 1), keys: make(grantKeys)}, nil
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
}
func clearState(state *accessState) { clearAccess(state); state.account = nil }
func (c *Client) syncStorageLocked() error {
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
	if err := c.syncStorageLocked(); err != nil {
		return Snapshot{}, err
	}
	if c.state.anchor != nil {
		if _, err := c.state.anchor.now(); err != nil {
			c.state.claims = nil
			c.state.anchor = nil
			c.state.generation++
		}
	}
	return c.snapshotLocked(), nil
}
func (c *Client) snapshotLocked() Snapshot {
	snapshot := Snapshot{Access: AccessDenied, Entitlements: make(map[string]bool), ReauthenticationRequired: true, StorageCapability: c.storageCapability}
	state := &c.state
	if state.credential != nil {
		snapshot.Access = AccessRefreshRequired
		expiry := state.credential.CredentialExpiresAt
		snapshot.CredentialExpiresAt = &expiry
		snapshot.ReauthenticationRequired = false
	}
	if state.claims == nil || state.anchor == nil {
		return snapshot
	}
	now, err := state.anchor.now()
	if err != nil {
		return snapshot
	}
	claims := state.claims
	expiry, refresh := claims.ExpiresAt, claims.RefreshAfter
	snapshot.ExpiresAt = &expiry
	snapshot.NextCheckAt = &refresh
	snapshot.ReauthenticationRequired = snapshot.CredentialExpiresAt == nil || *snapshot.CredentialExpiresAt <= saturatingAdd(now, 86400)
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
			snapshot.RemainingOfflineSeconds = uint64(claims.ExpiresAt - now)
		}
	}
	return snapshot
}

// Logout clears local access and customer session immediately. It neither
// revokes the remote session nor releases the occupied device slot.
func (c *Client) Logout() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	clearState(&c.state)
	return c.invalidateLocked()
}

func (c *Client) Activate(ctx context.Context, key, idempotencyKey string) (Snapshot, error) {
	return c.ActivateWithPrevious(ctx, key, "", idempotencyKey)
}
func (c *Client) ActivateWithPrevious(ctx context.Context, key, previousCredential, idempotencyKey string) (Snapshot, error) {
	return c.activate(ctx, key, "", previousCredential, idempotencyKey)
}
func (c *Client) activate(ctx context.Context, key, licence, previousCredential, idempotencyKey string) (Snapshot, error) {
	if (licence == "" && (key == "" || len(key) > 256)) || (licence != "" && !opaque(licence)) || !validOperationID(idempotencyKey) || (previousCredential != "" && !bearer(previousCredential)) {
		return Snapshot{}, ErrConfiguration
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
	body := c.scopeBody(map[string]any{"installation_id": c.device.InstallationID, "fingerprint": c.device.Fingerprint, "fingerprint_provider": c.device.FingerprintProvider, "previous_credential": optionalString(previousCredential), "idempotency_key": idempotencyKey})
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
	if err := c.invalidateLocked(); err != nil {
		c.mu.Unlock()
		return Snapshot{}, err
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
	return c.accept(ctx, budget, response, responseError, generation, nil, licence, started)
}

// Refresh validates the existing credential without extending its fixed expiry.
func (c *Client) Refresh(ctx context.Context) (Snapshot, error) {
	return c.refresh(ctx, false)
}

func (c *Client) refresh(ctx context.Context, respectRetry bool) (Snapshot, error) {
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
			c.mu.Unlock()
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
	response, responseError := c.transport.Post(budget, clientPrefix+"activations/"+saved.ActivationID+"/validate", c.credentialBody(saved), true)
	if budget.Err() != nil && ctx.Err() == nil {
		responseError = ErrTransient
	}
	return c.accept(ctx, budget, response, responseError, generation, saved, "", started)
}
func (c *Client) credentialBody(saved *StoredCredential) map[string]any {
	return c.scopeBody(map[string]any{"credential": saved.Credential, "installation_id": c.device.InstallationID, "fingerprint": c.device.Fingerprint, "fingerprint_provider": c.device.FingerprintProvider})
}

// Deactivate clears activation access before the request while retaining a
// customer login. Only a nil error confirms server-side slot release.
func (c *Client) Deactivate(ctx context.Context, idempotencyKey string) error {
	if !validOperationID(idempotencyKey) {
		return ErrConfiguration
	}
	c.mu.Lock()
	if err := c.syncStorageLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	saved := cloneCredential(c.state.credential)
	clearAccess(&c.state)
	if err := c.invalidateLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	generation := c.state.generation
	c.mu.Unlock()
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

// RequireAccess refreshes when needed, rechecks invalidation and expiry, and
// permits offline work only within a verified policy grant after an outage.
func (c *Client) RequireAccess(ctx context.Context, feature string) (Snapshot, error) {
	if ctx.Err() != nil {
		return Snapshot{}, ErrCancelled
	}
	snapshot, err := c.Snapshot()
	if err != nil {
		return Snapshot{}, err
	}
	if snapshot.Access == AccessRefreshRequired || snapshot.Access == AccessExpired || snapshot.Access == AccessOffline {
		if _, err := c.refresh(ctx, true); err != nil && !errors.Is(err, ErrTransient) {
			return Snapshot{}, err
		}
	}
	// Refresh may race a local logout or another context's invalidation. Obtain
	// the final decision from current state, never the returned request snapshot.
	snapshot, err = c.Snapshot()
	if err != nil {
		return Snapshot{}, err
	}
	if ctx.Err() != nil {
		return Snapshot{}, ErrCancelled
	}
	if snapshot.Access != AccessOnline && snapshot.Access != AccessOffline {
		return Snapshot{}, &Error{Kind: Denied, Code: "access_unavailable"}
	}
	if !snapshot.Entitlements[feature] {
		return Snapshot{}, &Error{Kind: Denied, Code: "feature_unavailable"}
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
	err := responseError
	verifying := err == nil
	if err == nil {
		saved, claims, anchor, err = c.verifyReply(budget, response, previous, licence, started)
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
			if err := c.storage.Save(c.state.storageVersion, *saved); err != nil {
				clearState(&c.state)
				if errors.Is(err, ErrStaleResponse) {
					return Snapshot{}, ErrStaleResponse
				}
				return Snapshot{}, ErrStorage
			}
			c.state.credential = cloneCredential(saved)
			c.state.claims = claims
			c.state.anchor = anchor
			c.state.transient = false
			c.state.nextRetry = 0
			c.state.retryAt = time.Time{}
			return c.snapshotLocked(), nil
		}
	}
	if errors.Is(err, ErrTransient) {
		var entropy [2]byte
		delaySeconds := int64(15)
		if _, randomError := rand.Read(entropy[:]); randomError == nil {
			delaySeconds += int64(uint16(entropy[0])<<8|uint16(entropy[1])) % 30
		}
		if verifying {
			// An unavailable signing key is no evidence for offline fallback.
			// Keep only the existing credential for a fresh validation attempt;
			// never save this unverified reply or its clock anchor.
			c.state.generation++
			c.state.claims = nil
		}
		c.state.transient = true
		c.state.nextRetry = delaySeconds
		c.state.retryAt = time.Now().Add(time.Duration(delaySeconds) * time.Second)
		if c.state.anchor != nil {
			if now, clockErr := c.state.anchor.now(); clockErr == nil {
				c.state.nextRetry = saturatingAdd(now, delaySeconds)
			}
		}
		snapshot := c.snapshotLocked()
		if snapshot.Access == AccessOffline {
			return snapshot, nil
		}
		return Snapshot{}, err
	}
	if errors.Is(err, ErrCancelled) && budget.Err() == nil {
		return Snapshot{}, ErrCancelled
	}
	clearState(&c.state)
	if storageErr := c.invalidateLocked(); storageErr != nil {
		return Snapshot{}, storageErr
	}
	if errors.Is(err, ErrCancelled) {
		return Snapshot{}, ErrInvalidResponse
	}
	return Snapshot{}, err
}

type grantReply struct {
	ActivationID        string  `json:"activation_id"`
	InstallationID      string  `json:"installation_id"`
	Credential          *string `json:"credential"`
	CredentialExpiresAt string  `json:"credential_expires_at"`
	Grant               *string `json:"grant"`
	ServerTime          string  `json:"server_time"`
	BindingMode         string  `json:"binding_mode"`
	FingerprintProvider *string `json:"fingerprint_provider"`
	LicenceExpiresAt    *string `json:"licence_expires_at"`
	SecretReplayExpired bool    `json:"secret_replay_expired"`
}

func (c *Client) verifyReply(ctx context.Context, data json.RawMessage, previous *StoredCredential, licence string, started requestStart) (*StoredCredential, *grantClaims, *timeAnchor, error) {
	var reply grantReply
	if decodeJSON(data, &reply) != nil {
		return nil, nil, nil, ErrInvalidResponse
	}
	if reply.SecretReplayExpired {
		return nil, nil, nil, ErrReauthenticationRequired
	}
	binding := "none"
	if c.device.Fingerprint != nil {
		binding = "hwid"
	}
	if !opaque(reply.ActivationID) || reply.InstallationID != c.device.InstallationID || !equalString(reply.FingerprintProvider, c.device.FingerprintProvider) || reply.BindingMode != binding || reply.Grant == nil {
		return nil, nil, nil, ErrInvalidResponse
	}
	server, err := timestamp(reply.ServerTime)
	if err != nil {
		return nil, nil, nil, err
	}
	anchor := &timeAnchor{server: server, requestStart: started}
	now, err := anchor.now()
	if err != nil {
		return nil, nil, nil, err
	}
	expiry, err := timestamp(reply.CredentialExpiresAt)
	if err != nil || expiry <= now || expiry > saturatingAdd(now, 30*86400) {
		return nil, nil, nil, ErrInvalidResponse
	}
	if previous != nil && (reply.ActivationID != previous.ActivationID || expiry != previous.CredentialExpiresAt || reply.Credential != nil) {
		return nil, nil, nil, ErrInvalidResponse
	}
	header, _, err := parseHeader(*reply.Grant)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, known := c.keys[header.KeyID]; !known {
		data, err := c.transport.Get(ctx, c.accountPath(jwksPath, ""))
		if err != nil {
			return nil, nil, nil, err
		}
		keys, err := parseKeys(data)
		if err != nil {
			return nil, nil, nil, err
		}
		c.keys = keys
	}
	var licenceExpiry *int64
	if reply.LicenceExpiresAt != nil {
		value, err := timestamp(*reply.LicenceExpiresAt)
		if err != nil {
			return nil, nil, nil, err
		}
		licenceExpiry = &value
	}
	now, err = anchor.now()
	if err != nil {
		return nil, nil, nil, err
	}
	if licence == "" && previous != nil {
		licence = previous.LicenceID
	}
	claims, err := verifyGrant(*reply.Grant, c.keys, expectedGrant{issuer: c.config.Issuer, application: c.config.ApplicationID, environment: c.config.EnvironmentID, licence: licence, activation: reply.ActivationID, installation: c.device.InstallationID, fingerprint: c.device.Fingerprint, fingerprintProvider: c.device.FingerprintProvider, credentialExpiresAt: expiry, licenceExpiresAt: licenceExpiry, now: now})
	if err != nil {
		return nil, nil, nil, err
	}
	credential := ""
	if reply.Credential != nil {
		credential = *reply.Credential
	} else if previous != nil {
		credential = previous.Credential
	}
	if !bearer(credential) {
		return nil, nil, nil, ErrInvalidResponse
	}
	saved := &StoredCredential{ApplicationID: c.config.ApplicationID, EnvironmentID: c.config.EnvironmentID, ActivationID: reply.ActivationID, LicenceID: claims.Subject, InstallationID: c.device.InstallationID, Credential: credential, CredentialExpiresAt: expiry, Fingerprint: cloneString(c.device.Fingerprint), FingerprintProvider: cloneString(c.device.FingerprintProvider)}
	return saved, claims, anchor, nil
}
func bearer(value string) bool           { return len(value) == 43 && asciiToken(value) }
func validOperationID(value string) bool { return len(value) >= 16 && len(value) <= 128 }
func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
