package orbit

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
)

const installedLimit = 64 * 1024
const installedSDK = "orbit.installed-client"

type installedScope struct {
	APIOrigin     string `json:"api_origin"`
	Issuer        string `json:"issuer"`
	ApplicationID string `json:"application_id"`
	EnvironmentID string `json:"environment_id"`
}
type installedIdentity struct {
	ID                  string  `json:"id"`
	Fingerprint         *string `json:"fingerprint"`
	FingerprintProvider *string `json:"fingerprint_provider"`
}
type installedCredential struct {
	ActivationID string `json:"activation_id"`
	LicenceID    string `json:"licence_id"`
	Bearer       string `json:"bearer"`
	ExpiresAt    *int64 `json:"expires_at"`
}
type installedPending struct {
	OperationID   string `json:"operation_id"`
	PrincipalKind string `json:"principal_kind"`
	InputDigest   string `json:"input_digest"`
	CreatedAt     int64  `json:"created_at"`
}
type installedAccess struct {
	JWS                string          `json:"jws"`
	JWKS               json.RawMessage `json:"jwks"`
	LicenceExpiresAt   *int64          `json:"licence_expires_at"`
	ReceivedServerTime int64           `json:"received_server_time"`
	ReceivedWallTime   int64           `json:"received_wall_time"`
	ServerHighWater    int64           `json:"server_high_water"`
	WallHighWater      int64           `json:"wall_high_water"`
}
type installedRecord struct {
	SDK          string               `json:"sdk"`
	Format       int                  `json:"format"`
	Provider     string               `json:"provider"`
	Scope        installedScope       `json:"scope"`
	Installation installedIdentity    `json:"installation"`
	Generation   uint64               `json:"generation"`
	Credential   *installedCredential `json:"credential"`
	Pending      *installedPending    `json:"pending_activation"`
	Access       *installedAccess     `json:"access"`
}

// Every envelope member is required, including nullable fields.
func exactInstalledShape(value any, kind reflect.Type) bool {
	if kind == reflect.TypeOf(json.RawMessage{}) {
		return true
	}
	if kind.Kind() == reflect.Pointer {
		return value == nil || exactInstalledShape(value, kind.Elem())
	}
	if value == nil {
		return false
	}
	if kind.Kind() != reflect.Struct {
		return true
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != kind.NumField() {
		return false
	}
	for i := 0; i < kind.NumField(); i++ {
		field := kind.Field(i)
		child, exists := object[strings.Split(field.Tag.Get("json"), ",")[0]]
		if !exists || !exactInstalledShape(child, field.Type) {
			return false
		}
	}
	return true
}

func decodeInstalled(data []byte, scope installedScope, provider string, fingerprint, fingerprintProvider *string) (installedRecord, error) {
	var record installedRecord
	value, err := uniqueJSON(data)
	if err != nil || !exactInstalledShape(value, reflect.TypeOf(record)) || json.Unmarshal(data, &record) != nil {
		return record, ErrStorage
	}
	identity := record.Installation
	if record.SDK != installedSDK || record.Format != 2 || record.Provider != provider || record.Scope != scope || record.Generation > math.MaxInt64 || !opaque(identity.ID) || len(identity.ID) < 16 || !equalString(identity.Fingerprint, fingerprint) || !equalString(identity.FingerprintProvider, fingerprintProvider) {
		return record, ErrStorage
	}
	if c := record.Credential; c != nil {
		if !opaque(c.ActivationID) || !opaque(c.LicenceID) || !bearer(c.Bearer) || c.ExpiresAt != nil && (*c.ExpiresAt <= 0 || *c.ExpiresAt > 253402300799) {
			return record, ErrStorage
		}
	}
	if p := record.Pending; p != nil {
		if !validOperationID(p.OperationID) || (p.PrincipalKind != "key" && p.PrincipalKind != "account") || !lowerHex(p.InputDigest, 64) || p.CreatedAt < 0 || p.CreatedAt > 253402300799 {
			return record, ErrStorage
		}
	}
	if a := record.Access; a != nil {
		if record.Credential == nil || len(a.JWS) == 0 || len(a.JWS) > 16384 || a.LicenceExpiresAt != nil && (*a.LicenceExpiresAt <= 0 || *a.LicenceExpiresAt > 253402300799) {
			return record, ErrStorage
		}
		var keySet struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if onlyFields(a.JWKS, "keys") != nil || json.Unmarshal(a.JWKS, &keySet) != nil || len(keySet.Keys) != 1 {
			return record, ErrStorage
		}
		if _, err := parseKeys(a.JWKS); err != nil {
			return record, ErrStorage
		}
		for _, stamp := range []int64{a.ReceivedServerTime, a.ReceivedWallTime, a.ServerHighWater, a.WallHighWater} {
			if stamp < 0 || stamp > 253402300799 {
				return record, ErrStorage
			}
		}
	}
	return record, nil
}
func (r installedRecord) storedCredential() *StoredCredential {
	if r.Credential == nil {
		return nil
	}
	c := r.Credential
	expiry := int64(0)
	if c.ExpiresAt != nil {
		expiry = *c.ExpiresAt
	}
	return &StoredCredential{ApplicationID: r.Scope.ApplicationID, EnvironmentID: r.Scope.EnvironmentID, InstallationID: r.Installation.ID, Fingerprint: cloneString(r.Installation.Fingerprint), FingerprintProvider: cloneString(r.Installation.FingerprintProvider), ActivationID: c.ActivationID, LicenceID: c.LicenceID, Credential: c.Bearer, CredentialExpiresAt: expiry}
}
