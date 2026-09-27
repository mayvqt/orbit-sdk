package orbit

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// UpdateOptions defaults to stable and the current supported desktop target.
type UpdateOptions struct{ Channel, Platform, Architecture string }
type Artifact struct {
	ID              string  `json:"id"`
	ReleaseID       string  `json:"release_id"`
	Platform        string  `json:"platform"`
	Architecture    string  `json:"architecture"`
	Filename        string  `json:"filename"`
	ByteLength      int64   `json:"byte_length"`
	SHA256          string  `json:"sha256"`
	DeliveryMode    string  `json:"delivery_mode"`
	URL             string  `json:"url"`
	RequiredFeature *string `json:"required_feature"`
}
type Release struct {
	ID            string     `json:"id"`
	Channel       string     `json:"channel"`
	Version       string     `json:"version"`
	Notes         string     `json:"notes"`
	ReleaseNumber *int64     `json:"release_number"`
	State         string     `json:"state"`
	CreatedAt     time.Time  `json:"created_at"`
	PublishedAt   *time.Time `json:"published_at"`
	Artifacts     []Artifact `json:"artifacts"`
}
type Update struct {
	Release  Release
	Artifact Artifact
}

// DownloadAuthorization holds a short-lived capability in memory. Do not cache
// it. AuthorizeDownload and Download are separate operations.
type DownloadAuthorization struct {
	artifact  Artifact
	ticket    string
	expiresAt *time.Time
}

func (a DownloadAuthorization) Artifact() Artifact {
	value := a.artifact
	if value.RequiredFeature != nil {
		v := *value.RequiredFeature
		value.RequiredFeature = &v
	}
	return value
}
func (a DownloadAuthorization) ExpiresAt() *time.Time {
	if a.expiresAt == nil {
		return nil
	}
	value := *a.expiresAt
	return &value
}
func (DownloadAuthorization) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("[Orbit download authorization redacted]"))
}
func (DownloadAuthorization) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func targetName(value string) bool {
	if len(value) < 1 || len(value) > 32 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func defaultUpdateOptions(options []UpdateOptions) (UpdateOptions, error) {
	if len(options) > 1 {
		return UpdateOptions{}, ErrConfiguration
	}
	o := UpdateOptions{}
	if len(options) == 1 {
		o = options[0]
	}
	if o.Channel == "" {
		o.Channel = "stable"
	}
	if o.Platform == "" {
		switch runtime.GOOS {
		case "linux", "windows":
			o.Platform = runtime.GOOS
		case "darwin":
			o.Platform = "macos"
		default:
			return o, ErrConfiguration
		}
	}
	if o.Architecture == "" {
		switch runtime.GOARCH {
		case "amd64":
			o.Architecture = "x64"
		case "arm64":
			o.Architecture = "arm64"
		case "386":
			o.Architecture = "x86"
		default:
			return o, ErrConfiguration
		}
	}
	if !targetName(o.Channel) || !targetName(o.Platform) || !targetName(o.Architecture) {
		return o, ErrConfiguration
	}
	return o, nil
}
func validDeliveryURL(value string, protected bool) bool {
	if protected {
		return validDownloadEndpoint(value)
	}
	if len(value) == 0 || len(value) > 2048 || !strings.HasPrefix(value, "https://") {
		return false
	}
	for _, b := range []byte(value) {
		if b <= 32 || b >= 127 || b == '\\' || b == '#' {
			return false
		}
	}
	if !validDownloadAuthority(strings.TrimPrefix(value, "https://")) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Fragment != "" {
		return false
	}
	base := strings.SplitN(value, "?", 2)[0]
	return validDownloadEndpoint(base)
}
func validArtifact(a Artifact) bool {
	return opaque(a.ID) &&
		opaque(a.ReleaseID) &&
		targetName(a.Platform) &&
		targetName(a.Architecture) &&
		len(a.Filename) > 0 &&
		len(a.Filename) <= 255 &&
		utf8.ValidString(a.Filename) &&
		a.Filename != "." &&
		a.Filename != ".." &&
		!strings.ContainsAny(a.Filename, "/\\") &&
		strings.IndexFunc(a.Filename, unicode.IsControl) < 0 &&
		safeUnits(a.ByteLength) &&
		lowerHex(a.SHA256, 64) &&
		(a.DeliveryMode == "public" ||
			a.DeliveryMode == "protected") &&
		validDeliveryURL(a.URL, a.DeliveryMode == "protected") &&
		(a.RequiredFeature == nil ||
			limitName(*a.RequiredFeature))
}
func parseArtifact(data []byte) (Artifact, error) {
	var a Artifact
	if !exactFields(data, "id", "release_id", "platform", "architecture", "filename", "byte_length", "sha256", "delivery_mode", "url", "required_feature") ||
		!requiredFields(data, "id", "release_id", "platform", "architecture", "filename", "byte_length", "sha256", "delivery_mode", "url") ||
		decodeJSON(data, &a) != nil ||
		!validArtifact(a) {
		return a, ErrInvalidResponse
	}
	return a, nil
}

// CheckForUpdates returns nil when no eligible newer release matches the exact target.
func (c *Client) CheckForUpdates(ctx context.Context, installedReleaseNumber int64, options ...UpdateOptions) (*Update, error) {
	o, err := defaultUpdateOptions(options)
	if err != nil || installedReleaseNumber < 0 || installedReleaseNumber > maxSafeInteger {
		return nil, ErrConfiguration
	}
	data, err := c.onlineService(ctx, "/updates", map[string]any{"channel": o.Channel, "platform": o.Platform, "architecture": o.Architecture, "installed_release_number": installedReleaseNumber})
	if err != nil {
		return nil, err
	}
	if !exactFields(data, "release", "artifact") {
		return nil, ErrInvalidResponse
	}
	var parts map[string]json.RawMessage
	_ = json.Unmarshal(data, &parts)
	if string(parts["release"]) == "null" && string(parts["artifact"]) == "null" {
		return nil, nil
	}
	a, err := parseArtifact(parts["artifact"])
	if err != nil {
		return nil, err
	}
	var r Release
	if !exactFields(parts["release"], "id", "channel", "version", "notes", "release_number", "state", "created_at", "published_at", "artifacts") ||
		!requiredFields(parts["release"], "id", "channel", "version", "notes", "release_number", "state", "created_at", "published_at", "artifacts") ||
		decodeJSON(parts["release"], &r) != nil ||
		!opaque(r.ID) ||
		r.ID != a.ReleaseID ||
		r.Channel != o.Channel ||
		a.Platform != o.Platform ||
		a.Architecture != o.Architecture ||
		r.ReleaseNumber == nil ||
		*r.ReleaseNumber <= installedReleaseNumber ||
		*r.ReleaseNumber > maxSafeInteger ||
		r.State != "published" ||
		len(r.Version) == 0 ||
		len(r.Version) > 64 ||
		len(r.Notes) > 8192 ||
		r.PublishedAt == nil ||
		!validServiceTime(r.CreatedAt) ||
		!validServiceTime(*r.PublishedAt) ||
		len(r.Artifacts) != 1 {
		return nil, ErrInvalidResponse
	}
	expected, _ := json.Marshal(a)
	actual, _ := json.Marshal(r.Artifacts[0])
	if string(actual) != string(expected) {
		return nil, ErrInvalidResponse
	}
	return &Update{Release: r, Artifact: a}, nil
}
func (c *Client) AuthorizeDownload(ctx context.Context, releaseID, artifactID string) (DownloadAuthorization, error) {
	if !opaque(releaseID) || !opaque(artifactID) {
		return DownloadAuthorization{}, ErrConfiguration
	}
	data, err := c.onlineService(ctx, "/downloads/authorize", map[string]any{"release_id": releaseID, "artifact_id": artifactID})
	if err != nil {
		return DownloadAuthorization{}, err
	}
	if !exactFields(data, "artifact", "ticket", "expires_at") {
		return DownloadAuthorization{}, ErrInvalidResponse
	}
	var parts map[string]json.RawMessage
	_ = json.Unmarshal(data, &parts)
	a, err := parseArtifact(parts["artifact"])
	if err != nil || a.ID != artifactID || a.ReleaseID != releaseID {
		return DownloadAuthorization{}, ErrInvalidResponse
	}
	var ticket *string
	var expires *time.Time
	if json.Unmarshal(parts["ticket"], &ticket) != nil || json.Unmarshal(parts["expires_at"], &expires) != nil {
		return DownloadAuthorization{}, ErrInvalidResponse
	}
	result := DownloadAuthorization{artifact: a, expiresAt: expires}
	if a.DeliveryMode == "public" {
		if ticket != nil || expires != nil {
			return DownloadAuthorization{}, ErrInvalidResponse
		}
	} else {
		if ticket == nil || len(*ticket) == 0 || len(*ticket) > 16*1024 || strings.IndexFunc(*ticket, func(r rune) bool { return r <= 32 || r >= 127 }) >= 0 || expires == nil || !validServiceTime(*expires) {
			return DownloadAuthorization{}, ErrInvalidResponse
		}
		result.ticket = *ticket
	}
	return result, nil
}

type DownloadOptions struct{ ReplaceExisting bool }

// Download streams directly from the seller into a private temporary file. It
// publishes verified bytes atomically and never executes or unpacks the file.
func (a DownloadAuthorization) Download(ctx context.Context, destination string, maxSize int64, options ...DownloadOptions) error {
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		MaxResponseHeaderBytes: 64 * 1024,
		DisableCompression:     true,
		DisableKeepAlives:      true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 30 * time.Minute}
	return a.download(ctx, destination, maxSize, client, options...)
}
func (a DownloadAuthorization) download(ctx context.Context, destination string, maxSize int64, client *http.Client, options ...DownloadOptions) error {
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if len(options) > 1 || destination == "" || !safeUnits(maxSize) || !validArtifact(a.artifact) || a.artifact.ByteLength > maxSize {
		return ErrConfiguration
	}
	if a.artifact.DeliveryMode == "protected" && (a.ticket == "" || a.expiresAt == nil || !time.Now().Before(*a.expiresAt)) {
		return &Error{Kind: Denied, Code: "download_authorization_expired"}
	}
	replace := len(options) == 1 && options[0].ReplaceExisting
	if !replace {
		if _, err := os.Lstat(destination); err == nil {
			return &Error{Kind: Configuration, Code: "destination_exists"}
		} else if !os.IsNotExist(err) {
			return ErrStorage
		}
	}
	temp, err := os.CreateTemp(filepath.Dir(destination), ".orbit-download-*")
	if err != nil {
		return ErrStorage
	}
	defer func() { _ = temp.Close(); _ = os.Remove(temp.Name()) }()
	current := a.artifact.URL
	var response *http.Response
	for redirects := 0; ; redirects++ {
		if !validDeliveryURL(current, false) {
			return ErrTransportSecurity
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			return ErrConfiguration
		}
		request.Header.Set("Accept-Encoding", "identity")
		if redirects == 0 && a.ticket != "" {
			request.Header.Set("Authorization", "Bearer "+a.ticket)
		}
		response, err = client.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return ErrCancelled
			}
			return classifyTransport(err)
		}
		if response.StatusCode == 301 || response.StatusCode == 302 || response.StatusCode == 303 || response.StatusCode == 307 || response.StatusCode == 308 {
			_ = response.Body.Close()
			if redirects >= 5 {
				return ErrInvalidResponse
			}
			location, err := response.Location()
			if err != nil {
				return ErrInvalidResponse
			}
			current = location.String()
			continue
		}
		break
	}
	defer response.Body.Close()
	if response.StatusCode != 200 ||
		response.Header.Get("Content-Encoding") != "" &&
			!strings.EqualFold(response.Header.Get("Content-Encoding"), "identity") ||
		response.ContentLength > maxSize ||
		response.ContentLength >= 0 &&
			response.ContentLength != a.artifact.ByteLength {
		return ErrInvalidResponse
	}
	digest := sha256.New()
	reader := io.LimitReader(response.Body, a.artifact.ByteLength+1)
	written, err := io.Copy(io.MultiWriter(temp, digest), reader)
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if err != nil || written != a.artifact.ByteLength || hex.EncodeToString(digest.Sum(nil)) != a.artifact.SHA256 {
		return ErrInvalidResponse
	}
	if temp.Sync() != nil || temp.Close() != nil {
		return ErrStorage
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if replace {
		err = os.Rename(temp.Name(), destination)
	} else {
		err = os.Link(temp.Name(), destination)
	}
	if err != nil {
		return ErrStorage
	}
	return nil
}
