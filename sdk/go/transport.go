package orbit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

const maxBytes = 64 * 1024
const operationTimeout = 30 * time.Second
const clientPrefix = "/api/client/v1/"
const jwksPath = "/.well-known/orbit-jwks.json"

// Transport owns a fixed trusted origin, mandatory certificate verification,
// disabled redirects and bounded request/response resources.
type Transport struct {
	base                 *url.URL
	client               *http.Client
	installationLifetime context.Context
	installationMu       sync.Mutex
	installationClosed   bool
	installationRequests sync.WaitGroup
}

// NewTransport accepts only an HTTPS origin without credentials, path or query.
func NewTransport(base string) (*Transport, error) { return newTransport(base, "https", false) }

func newTransport(base, scheme string, local bool) (*Transport, error) {
	if strings.IndexFunc(base, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return nil, ErrConfiguration
	}
	prefix := scheme + "://"
	if !strings.HasPrefix(base, prefix) {
		return nil, ErrConfiguration
	}
	authority := strings.TrimSuffix(strings.TrimPrefix(base, prefix), "/")
	if authority == "" || strings.ContainsAny(authority, "/\\@?#") {
		return nil, ErrConfiguration
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != scheme || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, ErrConfiguration
	}
	if local {
		ip := net.ParseIP(parsed.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return nil, ErrConfiguration
		}
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return nil, ErrConfiguration
		}
	}
	transport := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    3 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: maxBytes,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    2,
		MaxConnsPerHost:        4,
		IdleConnTimeout:        90 * time.Second,
		// A fresh connection per attempt prevents net/http's transparent retry
		// of safe reads on a reused connection from escaping our attempt budget.
		DisableKeepAlives:  true,
		DisableCompression: true,
	}
	if local {
		transport.Proxy = nil
	}
	return &Transport{base: parsed, client: &http.Client{
		Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// CloseIdleConnections releases idle connection resources. It does not cancel
// running calls; cancel the contexts supplied to those calls separately.
func (t *Transport) CloseIdleConnections() { t.client.CloseIdleConnections() }

func (t *Transport) endpoint(route string) (*url.URL, error) {
	if t == nil || t.base == nil || t.client == nil || len(route) > 2048 || strings.Contains(route, "//") || strings.ContainsAny(route, "\\#") || strings.IndexFunc(route, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return nil, ErrConfiguration
	}
	parts := strings.SplitN(route, "?", 2)
	name := parts[0]
	if !(strings.HasPrefix(name, clientPrefix) || name == jwksPath) || path.Clean(name) != name || strings.Contains(name, "%") {
		return nil, ErrConfiguration
	}
	if len(parts) == 2 {
		if name != jwksPath && name != clientPrefix+"licences" && name != clientPrefix+"sessions/current" {
			return nil, ErrConfiguration
		}
		pairs := strings.Split(parts[1], "&")
		if len(pairs) != 2 && !(name == clientPrefix+"licences" && len(pairs) == 3) {
			return nil, ErrConfiguration
		}
		for i, pair := range pairs {
			field := strings.SplitN(pair, "=", 2)
			if len(field) != 2 || field[0] != []string{"application_id", "environment_id", "after"}[i] || !opaque(field[1]) {
				return nil, ErrConfiguration
			}
		}
	}
	parsed, err := url.Parse(route)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Path != name {
		return nil, ErrConfiguration
	}
	return t.base.ResolveReference(parsed), nil
}

// Get performs a bounded safe read. JSON responses retain their original bytes
// so duplicate security fields cannot disappear before typed verification.
func (t *Transport) Get(ctx context.Context, route string) (json.RawMessage, error) {
	return t.request(ctx, http.MethodGet, route, nil, "", true)
}
func (t *Transport) GetBearer(ctx context.Context, route, token string) (json.RawMessage, error) {
	if strings.SplitN(route, "?", 2)[0] != clientPrefix+"licences" {
		return nil, ErrConfiguration
	}
	return t.request(ctx, http.MethodGet, route, nil, token, true)
}
func (t *Transport) DeleteBearer(ctx context.Context, route, token string) (json.RawMessage, error) {
	if strings.SplitN(route, "?", 2)[0] != clientPrefix+"sessions/current" {
		return nil, ErrConfiguration
	}
	return t.request(ctx, http.MethodDelete, route, nil, token, false)
}

// Post retries only when retrySafe is true; callers must ensure a read-only
// operation or a mutation with the same idempotency key and identical input.
func (t *Transport) Post(ctx context.Context, route string, body any, retrySafe bool) (json.RawMessage, error) {
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	var buffer limitedBody
	if err := json.NewEncoder(&buffer).Encode(body); err != nil {
		return nil, ErrConfiguration
	}
	return t.request(ctx, http.MethodPost, route, buffer.Bytes(), "", retrySafe)
}

type limitedBody struct{ bytes.Buffer }

func (b *limitedBody) Write(data []byte) (int, error) {
	if len(data) > maxBytes-b.Len() {
		return 0, ErrConfiguration
	}
	return b.Buffer.Write(data)
}

func (t *Transport) request(ctx context.Context, method, route string, body []byte, token string, safe bool) (json.RawMessage, error) {
	if t.installationLifetime != nil {
		t.installationMu.Lock()
		if t.installationClosed {
			t.installationMu.Unlock()
			return nil, ErrCancelled
		}
		t.installationRequests.Add(1)
		t.installationMu.Unlock()
		defer t.installationRequests.Done()
		child, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(t.installationLifetime, cancel)
		if t.installationLifetime.Err() != nil {
			cancel()
		}
		defer func() { stop(); cancel() }()
		ctx = child
	}

	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	endpoint, err := t.endpoint(route)
	if err != nil {
		return nil, err
	}
	if token != "" && (len(token) > 256 || !asciiToken(token)) {
		return nil, ErrConfiguration
	}
	if (method == http.MethodDelete || (method == http.MethodGet && strings.SplitN(route, "?", 2)[0] == clientPrefix+"licences")) && token == "" {
		return nil, ErrConfiguration
	}
	budget, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		result, retryAfter, err := t.attempt(budget, method, endpoint, body, token)
		if ctx.Err() != nil {
			return nil, ErrCancelled
		}
		if budget.Err() != nil {
			return nil, ErrTransient
		}
		if err == nil {
			return result, nil
		}
		if !safe || attempt == 2 || !errors.Is(err, ErrTransient) {
			return nil, err
		}
		var entropy [1]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, ErrTransportSecurity
		}
		delay := time.Duration((250+int(entropy[0]))<<attempt) * time.Millisecond
		if retryAfter > delay {
			delay = retryAfter
		}
		deadline, _ := budget.Deadline()
		if delay >= time.Until(deadline) {
			return nil, err
		}
		timer := time.NewTimer(delay)
		select {
		case <-budget.Done():
			timer.Stop()
			if ctx.Err() != nil {
				return nil, ErrCancelled
			}
			return nil, ErrTransient
		case <-timer.C:
		}
	}
	return nil, ErrTransient
}

type errorEnvelope struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id"`
	} `json:"error"`
}

func (t *Transport) attempt(ctx context.Context, method string, endpoint *url.URL, body []byte, token string) (json.RawMessage, time.Duration, error) {
	attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// A non-rewindable body prevents net/http from independently replaying a
	// mutation. This layer alone owns the bounded retry policy.
	var reader io.Reader
	if body != nil {
		reader = struct{ io.Reader }{bytes.NewReader(body)}
	}
	request, err := http.NewRequestWithContext(attempt, method, endpoint.String(), reader)
	if err != nil {
		return nil, 0, ErrConfiguration
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		request.ContentLength = int64(len(body))
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := t.client.Do(request)
	if err != nil {
		return nil, 0, classifyTransport(err)
	}
	defer response.Body.Close()
	if response.ContentLength > maxBytes {
		return nil, 0, ErrInvalidResponse
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return nil, 0, classifyTransport(err)
	}
	if len(data) > maxBytes {
		return nil, 0, ErrInvalidResponse
	}
	if response.StatusCode == http.StatusNoContent {
		if len(data) != 0 {
			return nil, 0, ErrInvalidResponse
		}
		return nil, 0, nil
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		if _, err := uniqueJSON(data); err != nil {
			return nil, 0, err
		}
		return data, 0, nil
	}
	status := response.StatusCode
	if status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout {
		var object map[string]json.RawMessage
		_ = json.Unmarshal(data, &object)
		if _, isOrbitEnvelope := object["error"]; !isOrbitEnvelope {
			// Reverse proxies can report an upstream outage without Orbit's JSON
			// envelope. No grant is accepted; preserve the credential for retry.
			return nil, 0, ErrTransient
		}
	}
	if status != 401 && status != 403 && status != 404 && status != 409 && status != 422 && status != 429 && (status < 500 || status > 599) {
		return nil, 0, ErrInvalidResponse
	}
	var envelope errorEnvelope
	if decodeJSON(data, &envelope) != nil {
		return nil, 0, ErrInvalidResponse
	}
	failure := envelope.Error
	if !errorCode(failure.Code) || failure.Message == "" || !validRequestID(failure.RequestID) {
		return nil, 0, ErrInvalidResponse
	}
	if status == 429 || status >= 500 {
		if !(status == 429 && failure.Code == "rate_limited" || status == 503 && failure.Code == "service_unavailable") {
			return nil, 0, ErrInvalidResponse
		}
		var after time.Duration
		if value := response.Header.Get("Retry-After"); value != "" && digits(value) {
			seconds, err := strconv.ParseUint(value, 10, 64)
			if err != nil || seconds >= uint64(operationTimeout/time.Second) {
				after = operationTimeout
			} else {
				after = time.Duration(seconds) * time.Second
			}
		}
		return nil, after, &Error{Kind: Transient, Code: failure.Code, RequestID: failure.RequestID}
	}
	return nil, 0, &Error{Kind: Denied, Code: failure.Code, RequestID: failure.RequestID}
}

func classifyTransport(err error) error {
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return ErrTransient
	}
	return ErrTransportSecurity
}
func asciiToken(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func opaque(value string) bool { return len(value) <= 128 && asciiToken(value) }
func digits(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func errorCode(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func (t *Transport) settleInstalledRequests() {
	t.installationMu.Lock()
	t.installationClosed = true
	t.installationMu.Unlock()
	t.installationRequests.Wait()
}
