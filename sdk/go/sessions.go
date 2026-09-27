package orbit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SessionMetadata describes the current in-memory floating seat. It is display
// metadata, never reusable authorization, and is not persisted.
type SessionMetadata struct {
	id           string
	sequence     int64
	expiresAt    time.Time
	refreshAfter time.Time
}

func (m SessionMetadata) ID() string              { return m.id }
func (m SessionMetadata) Sequence() int64         { return m.sequence }
func (m SessionMetadata) ExpiresAt() time.Time    { return m.expiresAt }
func (m SessionMetadata) RefreshAfter() time.Time { return m.refreshAfter }

type sessionRuntime struct {
	metadata        SessionMetadata
	grant           sessionGrant
	anchor          timeAnchor
	pendingSequence int64
}

type floatingSessionReply struct {
	SessionID  string `json:"session_id"`
	Sequence   int64  `json:"sequence"`
	ExpiresAt  string `json:"expires_at"`
	ServerTime string `json:"server_time"`
	Grant      string `json:"grant"`
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func (c *Client) sessionSnapshotLocked() Snapshot {
	snapshot := Snapshot{Access: AccessDenied, Entitlements: map[string]bool{}, ReauthenticationRequired: c.state.credential == nil, StorageCapability: c.storageCapability, UpdateAvailable: c.state.updateAvailable}
	if c.state.credential != nil {
		snapshot.Access = AccessRefreshRequired
		if c.state.credential.CredentialExpiresAt != 0 {
			expires := time.Unix(c.state.credential.CredentialExpiresAt, 0).UTC()
			snapshot.CredentialExpiresAt = &expires
		}
	}
	if c.state.session == nil {
		return snapshot
	}
	session := c.state.session
	metadata := session.metadata
	snapshot.Session = &metadata
	expires, refresh := metadata.expiresAt, metadata.refreshAfter
	snapshot.ExpiresAt, snapshot.NextCheckAt = &expires, &refresh
	now, err := session.anchor.now()
	if err != nil {
		c.state.session = nil
		return snapshot
	}
	if now >= session.grant.ExpiresAt {
		snapshot.Access = AccessExpired
		return snapshot
	}
	if expiry := c.state.sessionLicenceExpiresAt; expiry != nil && now >= *expiry {
		snapshot.Access = AccessExpired
		return snapshot
	}
	snapshot.Access = AccessOnline
	snapshot.Entitlements = make(map[string]bool, len(session.grant.Entitlements))
	for name, enabled := range session.grant.Entitlements {
		snapshot.Entitlements[name] = enabled
	}
	return snapshot
}

func sessionIDFromToken(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ErrInvalidResponse
	}
	headerBytes, err := canonicalBase64(parts[0])
	if err != nil || onlyFields(headerBytes, "alg", "typ", "kid") != nil {
		return "", ErrInvalidResponse
	}
	var header grantHeader
	if decodeJSON(headerBytes, &header) != nil || header.Algorithm != "ES256" || header.Type != "orbit-session+jwt" || !opaque(header.KeyID) {
		return "", ErrInvalidResponse
	}
	return header.KeyID, nil
}

func (c *Client) sessionProof(saved *StoredCredential) map[string]any {
	return c.scopeBody(map[string]any{
		"credential":           saved.Credential,
		"installation_id":      c.device.InstallationID,
		"fingerprint":          c.device.Fingerprint,
		"fingerprint_provider": c.device.FingerprintProvider,
	})
}

func (c *Client) verifySessionReply(ctx context.Context, data json.RawMessage, saved *StoredCredential, id string, sequence int64, started requestStart, licenceExpiry *int64) (*sessionRuntime, error) {
	var reply floatingSessionReply
	if decodeJSON(data, &reply) != nil {
		return nil, ErrInvalidResponse
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 5 || fields["session_id"] == nil || fields["sequence"] == nil || fields["expires_at"] == nil || fields["server_time"] == nil || fields["grant"] == nil || !opaque(reply.SessionID) || len(reply.SessionID) < 16 || reply.SessionID != id || reply.Sequence != sequence || reply.Grant == "" || len(reply.Grant) > 16*1024 {
		return nil, ErrInvalidResponse
	}
	expires, err := timestamp(reply.ExpiresAt)
	if err != nil {
		return nil, err
	}
	server, err := timestamp(reply.ServerTime)
	if err != nil {
		return nil, err
	}
	anchor := timeAnchor{server: server, requestStart: started}
	now, err := anchor.now()
	if err != nil {
		return nil, err
	}
	keyID, err := sessionIDFromToken(reply.Grant)
	if err != nil {
		return nil, err
	}
	if _, ok := c.sessionKeys.keys[keyID]; !ok {
		jwks, err := c.transport.Get(ctx, c.accountPath(jwksPath, ""))
		if err != nil {
			return nil, err
		}
		keys, err := parseSessionKeys(jwks, c.key.environment)
		if err != nil {
			return nil, err
		}
		c.sessionKeys = keys
	}
	var credentialExpiry *int64
	if saved.CredentialExpiresAt != 0 {
		credentialExpiry = cloneInt64(&saved.CredentialExpiresAt)
	}
	expected := sessionExpected{
		issuer: c.key.issuer, application: c.key.applicationID, environment: c.key.environmentID,
		licence: saved.LicenceID, activation: saved.ActivationID, installation: saved.InstallationID,
		fingerprint: saved.Fingerprint, fingerprintProvider: saved.FingerprintProvider,
		allowUnboundFingerprint: true, credentialExpiresAt: credentialExpiry,
		licenceExpiresAt: cloneInt64(licenceExpiry), now: now, sessionID: id, sequence: sequence,
	}
	verified, err := verifySessionGrant(reply.Grant, c.sessionKeys, expected)
	if err != nil || verified.ExpiresAt != expires || verified.Sequence != sequence || verified.SessionID != id {
		return nil, ErrInvalidResponse
	}
	expiresAt := time.Unix(verified.ExpiresAt, 0).UTC()
	refreshAt := time.Unix(verified.RefreshAfter, 0).UTC()
	return &sessionRuntime{
		metadata: SessionMetadata{id: id, sequence: sequence, expiresAt: expiresAt, refreshAfter: refreshAt},
		grant:    verified, anchor: anchor,
	}, nil
}

// StartSession acquires a floating seat when the confirmed licence policy
// requires one. For an ordinary licence it is a local no-op.
func (c *Client) StartSession(ctx context.Context) (Snapshot, error) {
	ctx, stop := c.operationContext(ctx)
	defer stop()
	if ctx.Err() != nil {
		return Snapshot{}, ErrCancelled
	}
	c.mu.Lock()
	if err := c.syncStorageLocked(); err != nil {
		c.mu.Unlock()
		return Snapshot{}, err
	}
	if c.state.offline != nil && c.state.offline.authorized {
		snapshot, err := c.checkedSnapshotLocked()
		c.mu.Unlock()
		return snapshot, err
	}
	known, required, saved := c.state.sessionPolicyKnown, c.state.sessionRequired, cloneCredential(c.state.credential)
	if known && !required {
		snapshot, err := c.checkedSnapshotLocked()
		c.mu.Unlock()
		return snapshot, err
	}
	c.mu.Unlock()
	if !known {
		if saved == nil {
			return Snapshot{}, ErrNotActivated
		}
		if _, err := c.Refresh(ctx); err != nil {
			return Snapshot{}, err
		}
	}
	generation, err := c.generation()
	if err != nil {
		return Snapshot{}, err
	}
	if err := c.lockOperation(ctx, generation); err != nil {
		return Snapshot{}, err
	}
	defer c.unlockOperation()
	return c.startSessionSerialized(ctx, generation, true)
}

func (c *Client) startSessionSerialized(ctx context.Context, generation uint64, explicit bool) (Snapshot, error) {
	c.mu.Lock()
	if err := c.syncStorageLocked(); err != nil {
		c.mu.Unlock()
		return Snapshot{}, err
	}
	if c.state.generation != generation {
		c.mu.Unlock()
		return Snapshot{}, ErrStaleResponse
	}
	if c.state.offline != nil && c.state.offline.authorized {
		snapshot, err := c.checkedSnapshotLocked()
		c.mu.Unlock()
		return snapshot, err
	}
	if !c.state.sessionRequired {
		snapshot, err := c.checkedSnapshotLocked()
		c.mu.Unlock()
		return snapshot, err
	}
	if explicit {
		c.state.sessionDisabled = false
	}
	if c.state.session != nil {
		snapshot := c.sessionSnapshotLocked()
		if snapshot.Access == AccessOnline {
			c.mu.Unlock()
			return snapshot, nil
		}
	}
	if c.state.sessionDisabled {
		c.mu.Unlock()
		return Snapshot{}, ErrSessionRequired
	}
	saved := cloneCredential(c.state.credential)
	if saved == nil {
		c.mu.Unlock()
		return Snapshot{}, ErrNotActivated
	}
	id := c.state.pendingSessionID
	if id != "" && time.Since(c.state.pendingSessionSince) >= 120*time.Second {
		go c.bestEffortEnd(saved, id)
		id = ""
	}
	if id == "" {
		device, err := NewInstallation()
		if err != nil {
			c.mu.Unlock()
			return Snapshot{}, err
		}
		id = device.InstallationID
		c.state.pendingSessionID = id
		c.state.pendingSessionSince = time.Now()
	}
	licenceExpiry := cloneInt64(c.state.sessionLicenceExpiresAt)
	body := c.sessionProof(saved)
	body["session_id"] = id
	path := fmt.Sprintf("%sactivations/%s/sessions", clientPrefix, saved.ActivationID)
	c.mu.Unlock()

	started, err := captureStart()
	if err != nil {
		return Snapshot{}, err
	}
	response, requestErr := c.transport.Post(ctx, path, body, true)
	var runtime *sessionRuntime
	if requestErr == nil {
		runtime, requestErr = c.verifySessionReply(ctx, response, saved, id, 1, started, licenceExpiry)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.syncStorageLocked(); err != nil {
		return Snapshot{}, err
	}
	if c.state.generation != generation {
		go c.bestEffortEnd(saved, id)
		return Snapshot{}, ErrStaleResponse
	}
	if ctx.Err() != nil || errors.Is(requestErr, ErrCancelled) {
		c.state.pendingSessionID = ""
		go c.bestEffortEnd(saved, id)
		return Snapshot{}, ErrCancelled
	}
	if requestErr != nil {
		if errors.Is(requestErr, ErrTransient) {
			c.state.sessionRetryAt = time.Now().Add(15 * time.Second)
			c.wakeInstalled()
		} else {
			c.state.sessionRetryAt = time.Time{}
			var denial *Error
			if errors.As(requestErr, &denial) && (denial.Code == "session_expired" || denial.Code == "session_ended" || denial.Code == "session_sequence_conflict") {
				c.state.pendingSessionID = ""
			}
		}
		return Snapshot{}, requestErr
	}
	c.state.session = runtime
	c.state.pendingSessionID = ""
	c.state.sessionRetryAt = time.Time{}
	c.wakeInstalled()
	snapshot := c.sessionSnapshotLocked()
	if snapshot.Access != AccessOnline {
		return Snapshot{}, ErrSessionRequired
	}
	return snapshot, nil
}

func (c *Client) bestEffortEnd(saved *StoredCredential, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if saved == nil || !opaque(id) || len(id) < 16 {
		return
	}
	path := fmt.Sprintf("%sactivations/%s/sessions/%s/end", clientPrefix, saved.ActivationID, id)
	_, _ = c.transport.postCleanup(ctx, path, c.sessionProof(saved))
}

func (c *Client) sendEnd(ctx context.Context, saved *StoredCredential, id string) error {
	if saved == nil || !opaque(id) || len(id) < 16 {
		return ErrConfiguration
	}
	body := c.sessionProof(saved)
	path := fmt.Sprintf("%sactivations/%s/sessions/%s/end", clientPrefix, saved.ActivationID, id)
	response, err := c.transport.Post(ctx, path, body, true)
	if err != nil {
		return err
	}
	if response != nil {
		return ErrInvalidResponse
	}
	return nil
}

// EndSession clears local session authority before requesting seat release.
// A failed release never restores that authority; the server expires it.
func (c *Client) EndSession(ctx context.Context) error {
	ctx, stop := c.operationContext(ctx)
	defer stop()
	c.mu.Lock()
	if err := c.syncStorageLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	if c.state.offline != nil && c.state.offline.authorized {
		c.mu.Unlock()
		return nil
	}
	known, required, saved := c.state.sessionPolicyKnown, c.state.sessionRequired, cloneCredential(c.state.credential)
	if known && !required {
		c.mu.Unlock()
		return nil
	}
	if !known {
		c.state.sessionDisabled = true
	}
	c.mu.Unlock()
	if !known {
		if saved == nil {
			return nil
		}
		if _, err := c.refreshWithoutSessionAcquire(ctx); err != nil {
			return err
		}
	}
	c.mu.Lock()
	if err := c.syncStorageLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	if !c.state.sessionRequired {
		c.mu.Unlock()
		return nil
	}
	session := c.state.session
	id := c.state.pendingSessionID
	if session != nil {
		id = session.metadata.id
	}
	saved = cloneCredential(c.state.credential)
	c.state.session = nil
	c.state.pendingSessionID = ""
	c.state.sessionDisabled = true
	c.state.sessionRetryAt = time.Time{}
	c.state.generation++
	c.mu.Unlock()
	if id == "" || saved == nil {
		return nil
	}
	return c.sendEnd(ctx, saved, id)
}

func (c *Client) renewSession(ctx context.Context, generation uint64) (Snapshot, error) {
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
	session, saved := c.state.session, cloneCredential(c.state.credential)
	if session == nil || saved == nil {
		c.mu.Unlock()
		return Snapshot{}, ErrSessionRequired
	}
	sequence := session.pendingSequence
	if sequence == 0 {
		sequence = session.metadata.sequence + 1
		session.pendingSequence = sequence
	}
	id := session.metadata.id
	licenceExpiry := cloneInt64(c.state.sessionLicenceExpiresAt)
	body := c.sessionProof(saved)
	body["sequence"] = sequence
	path := fmt.Sprintf("%sactivations/%s/sessions/%s/renew", clientPrefix, saved.ActivationID, id)
	c.mu.Unlock()

	started, err := captureStart()
	if err != nil {
		return Snapshot{}, err
	}
	response, requestErr := c.transport.Post(ctx, path, body, true)
	var replacement *sessionRuntime
	if requestErr == nil {
		replacement, requestErr = c.verifySessionReply(ctx, response, saved, id, sequence, started, licenceExpiry)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.syncStorageLocked(); err != nil {
		return Snapshot{}, err
	}
	if c.state.generation != generation {
		return Snapshot{}, ErrStaleResponse
	}
	if ctx.Err() != nil {
		c.state.session = nil
		c.state.sessionDisabled = true
		return Snapshot{}, ErrCancelled
	}
	if requestErr != nil {
		if errors.Is(requestErr, ErrTransient) {
			c.state.sessionRetryAt = time.Now().Add(15 * time.Second)
			c.wakeInstalled()
		} else {
			c.state.session = nil
			c.state.sessionRetryAt = time.Time{}
			c.state.sessionDisabled = true
			var failure *Error
			if errors.As(requestErr, &failure) && failure.Code == "session_expired" {
				c.state.pendingSessionID = ""
				c.state.sessionDisabled = false
				c.state.sessionRetryAt = time.Now().Add(15 * time.Second)
			}
		}
		return Snapshot{}, requestErr
	}
	if c.state.session == nil || c.state.session.metadata.id != id || c.state.session.pendingSequence != sequence {
		return Snapshot{}, ErrStaleResponse
	}
	c.state.session = replacement
	c.state.sessionRetryAt = time.Time{}
	c.wakeInstalled()
	snapshot := c.sessionSnapshotLocked()
	if snapshot.Access != AccessOnline {
		return Snapshot{}, ErrSessionRequired
	}
	return snapshot, nil
}
