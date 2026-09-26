package orbit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"sync"
	"time"
)

type installedFiles interface {
	read() ([]byte, error)
	write([]byte) error
	check() error
	close() error
}
type installedStorage struct {
	mu       sync.Mutex
	files    installedFiles
	record   installedRecord
	poisoned bool
	closed   bool
}

func (s *installedStorage) checkLocked() error {
	if s.closed || s.poisoned || s.files.check() != nil {
		return ErrStorage
	}
	return nil
}
func (s *installedStorage) writeLocked(record installedRecord) error {
	if err := s.checkLocked(); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil || len(data) > installedLimit {
		return ErrStorage
	}
	defer clear(data)
	if s.files.write(data) != nil {
		s.poisoned = true
		return ErrStorage
	}
	s.record = record
	return nil
}
func (s *installedStorage) Load() (uint64, *StoredCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkLocked(); err != nil {
		return 0, nil, err
	}
	return s.record.Generation, s.record.storedCredential(), nil
}
func (s *installedStorage) Version() (uint64, error) {
	version, _, err := s.Load()
	return version, err
}
func (s *installedStorage) Save(version uint64, credential StoredCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if version != s.record.Generation {
		return ErrStaleResponse
	}
	r := s.record
	r.Credential, r.Access = installedCredentialFrom(&credential), nil
	return s.writeLocked(r)
}
func installedCredentialFrom(c *StoredCredential) *installedCredential {
	if c == nil {
		return nil
	}
	r := &installedCredential{ActivationID: c.ActivationID, LicenceID: c.LicenceID, Bearer: c.Credential}
	if c.CredentialExpiresAt != 0 {
		expiry := c.CredentialExpiresAt
		r.ExpiresAt = &expiry
	}
	return r
}
func (s *installedStorage) Invalidate() (uint64, error) { return s.invalidate(true) }
func (s *installedStorage) invalidate(clearPending bool) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.record
	if r.Generation == math.MaxInt64 {
		return 0, ErrStorage
	}
	r.Generation++
	r.Credential, r.Access = nil, nil
	if clearPending {
		r.Pending = nil
	}
	return r.Generation, s.writeLocked(r)
}
func (s *installedStorage) dropCache() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record.Access == nil {
		return s.checkLocked()
	}
	r := s.record
	r.Access = nil
	return s.writeLocked(r)
}
func (s *installedStorage) begin(key, licence, previous, operation string) (string, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.record
	kind, input := "key", key
	if licence != "" {
		kind, input = "account", licence
	}
	// Marshaling maps recursively sorts keys; retain only this scoped digest.
	encoded, err := json.Marshal(map[string]any{"scope": map[string]any{"api_origin": r.Scope.APIOrigin, "issuer": r.Scope.Issuer, "application_id": r.Scope.ApplicationID, "environment_id": r.Scope.EnvironmentID}, "installation": map[string]any{"id": r.Installation.ID, "fingerprint": r.Installation.Fingerprint, "fingerprint_provider": r.Installation.FingerprintProvider}, "principal_kind": kind, "licence_input": input, "previous_credential": optionalString(previous), "credential_mode": "persistent"})
	if err != nil {
		return "", 0, ErrConfiguration
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	hexDigest := hex.EncodeToString(digest[:])
	now := time.Now().Unix()
	if now < 0 {
		return "", 0, ErrClockUncertain
	}
	if p := r.Pending; p != nil {
		if now < p.CreatedAt || now-p.CreatedAt >= 86400 {
			return "", 0, ErrPendingActivationExpired
		}
		if p.InputDigest != hexDigest || p.PrincipalKind != kind || operation != "" && operation != p.OperationID {
			return "", 0, ErrPendingActivation
		}
		operation = p.OperationID
	} else {
		if operation == "" {
			device, err := NewInstallation()
			if err != nil {
				return "", 0, err
			}
			operation = device.InstallationID
		}
		r.Pending = &installedPending{OperationID: operation, PrincipalKind: kind, InputDigest: hexDigest, CreatedAt: now}
	}
	if r.Generation == math.MaxInt64 {
		return "", 0, ErrStorage
	}
	r.Generation++
	r.Credential, r.Access = nil, nil
	return operation, r.Generation, s.writeLocked(r)
}
func (s *installedStorage) commit(version uint64, credential *StoredCredential, response json.RawMessage, keys grantKeys, anchor *timeAnchor) error {
	var reply grantReply
	if decodeJSON(response, &reply) != nil || reply.Grant == nil {
		return ErrStorage
	}
	header, _, err := parseHeader(*reply.Grant)
	if err != nil {
		return ErrStorage
	}
	key := keys[header.KeyID]
	if key == nil {
		return ErrStorage
	}
	set, err := json.Marshal(map[string]any{"keys": []jsonWebKey{{KeyType: "EC", Curve: "P-256", Algorithm: "ES256", Purpose: "sig", KeyID: header.KeyID, X: base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}}})
	if err != nil {
		return ErrStorage
	}
	now, err := anchor.now()
	if err != nil {
		return err
	}
	var licenceExpiry *int64
	if reply.LicenceExpiresAt != nil {
		expiry, err := timestamp(*reply.LicenceExpiresAt)
		if err != nil {
			return err
		}
		licenceExpiry = &expiry
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if version != s.record.Generation {
		return ErrStaleResponse
	}
	r := s.record
	r.Credential, r.Pending = installedCredentialFrom(credential), nil
	r.Access = &installedAccess{JWS: *reply.Grant, JWKS: set, LicenceExpiresAt: licenceExpiry, ReceivedServerTime: anchor.server, ReceivedWallTime: anchor.wall, ServerHighWater: now, WallHighWater: time.Now().Unix()}
	return s.writeLocked(r)
}
func (s *installedStorage) checkpoint(server, wall int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.record.Access == nil {
		return s.checkLocked()
	}
	r := s.record
	access := *r.Access
	if server < access.ServerHighWater || wall < access.WallHighWater || server > 253402300799 || wall > 253402300799 ||
		(server-access.ReceivedServerTime)-(wall-access.ReceivedWallTime) < -30 || (server-access.ReceivedServerTime)-(wall-access.ReceivedWallTime) > 30 {
		return ErrClockUncertain
	}
	access.ServerHighWater, access.WallHighWater = server, wall
	r.Access = &access
	return s.writeLocked(r)
}
func (s *installedStorage) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.record = installedRecord{}
	return s.files.close()
}
