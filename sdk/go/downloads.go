package orbit

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const downloadMaxTime int64 = 253402300799

// DownloadTicketVerifier verifies a seller endpoint's short-lived download
// tickets. It has no network behavior and retains only parsed trusted keys.
type DownloadTicketVerifier struct {
	app      AppKey
	endpoint string
	keys     grantKeys
}

// DownloadTicket is verified artifact metadata. It contains no bearer token.
type DownloadTicket struct {
	licenceID  string
	releaseID  string
	artifactID string
	sha256     string
	byteLength int64
	ticketID   string
	issuedAt   time.Time
	expiresAt  time.Time
}

func (t DownloadTicket) LicenceID() string    { return t.licenceID }
func (t DownloadTicket) ReleaseID() string    { return t.releaseID }
func (t DownloadTicket) ArtifactID() string   { return t.artifactID }
func (t DownloadTicket) SHA256() string       { return t.sha256 }
func (t DownloadTicket) ByteLength() int64    { return t.byteLength }
func (t DownloadTicket) TicketID() string     { return t.ticketID }
func (t DownloadTicket) IssuedAt() time.Time  { return t.issuedAt }
func (t DownloadTicket) ExpiresAt() time.Time { return t.expiresAt }

var (
	errInvalidDownloadEndpoint = &Error{Kind: Configuration, Code: "invalid_download_endpoint"}
	errInvalidDownloadKeys     = &Error{Kind: Configuration, Code: "invalid_download_keys"}
	errInvalidDownloadTicket   = &Error{Kind: Denied, Code: "invalid_download_ticket"}
)

// NewDownloadTicketVerifier copies and validates the configured public JWKS.
// Invalid configuration returns an ErrConfiguration match whose Code names the
// rejected input.
func NewDownloadTicketVerifier(appKey, endpoint string, trustedJWKS []byte) (*DownloadTicketVerifier, error) {
	app, err := ParseAppKey(appKey)
	if err != nil {
		return nil, err
	}
	if !validDownloadEndpoint(endpoint) {
		return nil, errInvalidDownloadEndpoint
	}
	if len(trustedJWKS) == 0 || len(trustedJWKS) > 16*1024 || onlyFields(trustedJWKS, "keys") != nil {
		return nil, errInvalidDownloadKeys
	}
	keys, err := parseKeys(append([]byte(nil), trustedJWKS...))
	if err != nil {
		return nil, errInvalidDownloadKeys
	}
	prefix := string(app.environment) + "-"
	for kid := range keys {
		if !opaque(kid) || !strings.HasPrefix(kid, prefix) || len(kid) == len(prefix) {
			return nil, errInvalidDownloadKeys
		}
	}
	return &DownloadTicketVerifier{app: app, endpoint: endpoint, keys: keys}, nil
}

func validDownloadEndpoint(endpoint string) bool {
	if len(endpoint) < 1 || len(endpoint) > 2048 || !strings.HasPrefix(endpoint, "https://") {
		return false
	}
	if !validDownloadAuthority(strings.TrimPrefix(endpoint, "https://")) {
		return false
	}
	for i := 0; i < len(endpoint); i++ {
		c := endpoint[i]
		if c <= 32 || c >= 127 || strings.ContainsRune(`\\?#<>"{}|^`+"`", rune(c)) {
			return false
		}
		if c == '%' {
			if i+2 >= len(endpoint) || !isHex(endpoint[i+1]) || !isHex(endpoint[i+2]) {
				return false
			}
			i += 2
		}
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return false
	}
	if _, err := validateOrigin("https://"+parsed.Host, "https", false); err != nil {
		return false
	}
	return true
}

func validDownloadAuthority(rest string) bool {
	authority := rest
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	if authority == "" || strings.ContainsAny(authority, "@%\\") {
		return false
	}
	var port string
	if strings.HasPrefix(authority, "[") {
		close := strings.IndexByte(authority, ']')
		if close < 2 {
			return false
		}
		address, err := netip.ParseAddr(authority[1:close])
		if err != nil || !address.Is6() {
			return false
		}
		suffix := authority[close+1:]
		if suffix != "" {
			if !strings.HasPrefix(suffix, ":") || strings.Contains(suffix[1:], ":") {
				return false
			}
			port = suffix[1:]
		}
	} else {
		if strings.ContainsAny(authority, "[]") || strings.Count(authority, ":") > 1 {
			return false
		}
		if strings.Contains(authority, ":") {
			host, rawPort, _ := strings.Cut(authority, ":")
			if host == "" {
				return false
			}
			port = rawPort
		}
	}
	if port == "" {
		return !strings.HasSuffix(authority, ":")
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	number, err := strconv.Atoi(port)
	return err == nil && number >= 1 && number <= 65535
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

type downloadHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

type downloadClaims struct {
	Version       int64  `json:"ver"`
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	Subject       string `json:"sub"`
	TicketID      string `json:"jti"`
	IssuedAt      int64  `json:"iat"`
	NotBefore     int64  `json:"nbf"`
	ExpiresAt     int64  `json:"exp"`
	ApplicationID string `json:"application_id"`
	EnvironmentID string `json:"environment_id"`
	ReleaseID     string `json:"release_id"`
	ArtifactID    string `json:"artifact_id"`
	SHA256        string `json:"sha256"`
	ByteLength    int64  `json:"byte_length"`
}

// Verify checks the token using the current clock, or an optional explicit
// instant from a trusted application clock. Any invalid or expired ticket
// returns an ErrDenied match with Code "invalid_download_ticket". The verifier
// is immutable and safe for concurrent use.
func (v *DownloadTicketVerifier) Verify(token string, at ...time.Time) (DownloadTicket, error) {
	var zero DownloadTicket
	if v == nil || len(at) > 1 {
		return zero, errInvalidDownloadTicket
	}
	now := time.Now().UTC()
	if len(at) == 1 {
		now = at[0]
	}
	if now.IsZero() || now.Unix() < 0 || now.After(time.Unix(downloadMaxTime, 0)) {
		return zero, errInvalidDownloadTicket
	}
	if len(token) == 0 || len(token) > 16*1024 || !isASCII(token) {
		return zero, errInvalidDownloadTicket
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return zero, errInvalidDownloadTicket
	}
	headerBytes, err := canonicalBase64(parts[0])
	if err != nil || onlyFields(headerBytes, "alg", "typ", "kid") != nil {
		return zero, errInvalidDownloadTicket
	}
	var header downloadHeader
	if decodeJSON(headerBytes, &header) != nil || header.Algorithm != "ES256" || header.Type != "orbit-download+jwt" || !opaque(header.KeyID) {
		return zero, errInvalidDownloadTicket
	}
	key := v.keys[header.KeyID]
	if key == nil {
		return zero, errInvalidDownloadTicket
	}
	payload, err := canonicalBase64(parts[1])
	if err != nil {
		return zero, errInvalidDownloadTicket
	}
	signature, err := canonicalBase64(parts[2])
	if err != nil || len(signature) != 64 {
		return zero, errInvalidDownloadTicket
	}
	claimsValue, err := uniqueJSON(payload)
	if err != nil {
		return zero, errInvalidDownloadTicket
	}
	claimsObject, ok := claimsValue.(map[string]any)
	if !ok || len(claimsObject) != 14 {
		return zero, errInvalidDownloadTicket
	}
	for _, field := range []string{"ver", "iss", "aud", "sub", "jti", "iat", "nbf", "exp", "application_id", "environment_id", "release_id", "artifact_id", "sha256", "byte_length"} {
		if _, present := claimsObject[field]; !present {
			return zero, errInvalidDownloadTicket
		}
	}
	var claims downloadClaims
	if decodeJSON(payload, &claims) != nil || claims.Version != 1 || !opaque(claims.Subject) || !opaque(claims.TicketID) || !opaque(claims.ApplicationID) || !opaque(claims.EnvironmentID) || !opaque(claims.ReleaseID) || !opaque(claims.ArtifactID) || !lowerHex(claims.SHA256, 64) || claims.IssuedAt < 0 || claims.IssuedAt > downloadMaxTime || claims.NotBefore != claims.IssuedAt || claims.ExpiresAt < 0 || claims.ExpiresAt > downloadMaxTime || claims.ByteLength < 1 || claims.ByteLength > 9007199254740991 {
		return zero, errInvalidDownloadTicket
	}
	if claims.Issuer != v.app.issuer || claims.Audience != v.endpoint || claims.ApplicationID != v.app.applicationID || claims.EnvironmentID != v.app.environmentID || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 120 || time.Unix(claims.IssuedAt, 0).After(now.Add(30*time.Second)) || !time.Unix(claims.ExpiresAt, 0).After(now) {
		return zero, errInvalidDownloadTicket
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(key, hash[:], r, s) {
		return zero, errInvalidDownloadTicket
	}
	return DownloadTicket{licenceID: claims.Subject, releaseID: claims.ReleaseID, artifactID: claims.ArtifactID, sha256: claims.SHA256, byteLength: claims.ByteLength, ticketID: claims.TicketID, issuedAt: time.Unix(claims.IssuedAt, 0).UTC(), expiresAt: time.Unix(claims.ExpiresAt, 0).UTC()}, nil
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] > 0x7f {
			return false
		}
	}
	return true
}
