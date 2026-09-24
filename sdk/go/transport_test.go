package orbit

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Body != nil {
		defer request.Body.Close()
	}
	return f(request)
}

func testResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}
}

func testTransport(t *testing.T, handler roundTripFunc) *Transport {
	t.Helper()
	transport, err := NewTransport("https://orbit.example.test")
	if err != nil {
		t.Fatal(err)
	}
	transport.client.Transport = handler
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

func TestTransportRedirectAndTLSFailClosed(t *testing.T) {
	for _, kind := range []string{"redirect", "tls"} {
		t.Run(kind, func(t *testing.T) {
			var requests atomic.Int32
			transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
				requests.Add(1)
				if kind == "tls" {
					return nil, x509.UnknownAuthorityError{Cert: &x509.Certificate{}}
				}
				response := testResponse(request, http.StatusFound, "")
				response.Header.Set("Location", "https://untrusted.example.test/capture")
				return response, nil
			})
			_, err := transport.GetBearer(context.Background(), clientPrefix+"licences?application_id=app&environment_id=test", strings.Repeat("s", 43))
			expected := ErrInvalidResponse
			if kind == "tls" {
				expected = ErrTransportSecurity
			}
			if !errors.Is(err, expected) {
				t.Fatalf("got %v, want %v", err, expected)
			}
			if requests.Load() != 1 {
				t.Fatalf("redirect/security failure sent %d requests", requests.Load())
			}
			if strings.Contains(err.Error(), strings.Repeat("s", 43)) {
				t.Fatal("transport error exposed bearer")
			}
		})
	}
}

func TestCancelledBeforeRequestSendsNothing(t *testing.T) {
	var requests atomic.Int32
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		return testResponse(request, http.StatusOK, `{}`), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	operations := []func() error{
		func() error { _, err := transport.Get(ctx, jwksPath); return err },
		func() error {
			_, err := transport.Post(ctx, clientPrefix+"sessions", map[string]string{"password": "synthetic secret"}, false)
			return err
		},
		func() error {
			_, err := transport.GetBearer(ctx, clientPrefix+"licences?application_id=app&environment_id=test", strings.Repeat("s", 43))
			return err
		},
		func() error {
			_, err := transport.DeleteBearer(ctx, clientPrefix+"sessions/current?application_id=app&environment_id=test", strings.Repeat("s", 43))
			return err
		},
	}
	for _, operation := range operations {
		if err := operation(); !errors.Is(err, ErrCancelled) || strings.Contains(err.Error(), "synthetic secret") {
			t.Fatalf("unexpected cancellation result: %v", err)
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("cancelled operations sent %d requests", requests.Load())
	}
}

// Use the production HTTP transport and a trusted local certificate so retries,
// request replay and cancellation also exercise net/http's actual wire behavior.
func fixtureTransport(t *testing.T, handler http.HandlerFunc) *Transport {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	transport, err := NewTransport(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	trust.AddCert(server.Certificate())
	transport.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = trust
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

func TestTransportRetriesPreserveMutation(t *testing.T) {
	for _, status := range []int{429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			type requestRecord struct {
				method, route, accept, contentType, body string
			}
			requests := make(chan requestRecord, 4)
			var attempts atomic.Int32
			transport := fixtureTransport(t, func(w http.ResponseWriter, request *http.Request) {
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Error(err)
				}
				requests <- requestRecord{request.Method, request.URL.RequestURI(), request.Header.Get("Accept"), request.Header.Get("Content-Type"), string(body)}
				if attempts.Add(1) < 3 {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(status)
					code := "service_unavailable"
					if status == http.StatusTooManyRequests {
						code = "rate_limited"
					}
					_, _ = io.WriteString(w, `{"error":{"code":"`+code+`","message":"Retry","request_id":"request"}}`)
					return
				}
				_, _ = io.WriteString(w, `{"accepted":true}`)
			})
			body := map[string]string{"idempotency_key": "operation_123456", "licence_key": "synthetic-key"}
			data, err := transport.Post(context.Background(), clientPrefix+"activations", body, true)
			if err != nil || string(data) != `{"accepted":true}` || attempts.Load() != 3 {
				t.Fatalf("retry result = %s, %v; requests = %d", data, err, attempts.Load())
			}
			first := <-requests
			if first.method != http.MethodPost || first.route != clientPrefix+"activations" || first.accept != "application/json" || first.contentType != "application/json" || !strings.Contains(first.body, `"idempotency_key":"operation_123456"`) {
				t.Fatalf("unexpected wire request: %+v", first)
			}
			for i := 1; i < 3; i++ {
				if next := <-requests; !reflect.DeepEqual(next, first) {
					t.Fatalf("retry changed request: %+v, first %+v", next, first)
				}
			}
		})
	}
}

func TestTransportTerminalResponsesAreNotRetried(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"credentials", 401, `{"error":{"code":"invalid_credentials","message":"Denied","request_id":"request"}}`, ErrDenied},
		{"policy", 403, `{"error":{"code":"licence_revoked","message":"Denied","request_id":"request"}}`, ErrDenied},
		{"unknown", 409, `{"error":{"code":"future_error","message":"Unknown","request_id":"request"}}`, ErrDenied},
		{"unknown_outage", 503, `{"error":{"code":"future_error","message":"Unknown","request_id":"request"}}`, ErrInvalidResponse},
		{"denial_outage", 503, `{"error":{"code":"licence_revoked","message":"Denied","request_id":"request"}}`, ErrInvalidResponse},
		{"mismatched_rate_limit", 429, `{"error":{"code":"service_unavailable","message":"Unknown","request_id":"request"}}`, ErrInvalidResponse},
		{"unexpected_server_error", 500, `{"error":{"code":"service_unavailable","message":"Unknown","request_id":"request"}}`, ErrInvalidResponse},
		{"unexpected_gateway_error", 502, `{"error":{"code":"service_unavailable","message":"Unknown","request_id":"request"}}`, ErrInvalidResponse},
		{"unexpected_gateway_timeout", 504, `{"error":{"code":"service_unavailable","message":"Unknown","request_id":"request"}}`, ErrInvalidResponse},
		{"malformed_outage", 503, `{"error":{"code":"service_unavailable"}}`, ErrInvalidResponse},
		{"duplicate_outage_code", 503, `{"error":{"code":"service_unavailable","code":"licence_revoked","message":"Invalid","request_id":"request"}}`, ErrInvalidResponse},
		{"oversized_outage", 503, strings.Repeat(" ", maxBytes+1), ErrInvalidResponse},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var requests atomic.Int32
			transport := fixtureTransport(t, func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(fixture.status)
				_, _ = io.WriteString(w, fixture.body)
			})
			_, err := transport.Get(context.Background(), jwksPath)
			if !errors.Is(err, fixture.want) || requests.Load() != 1 {
				t.Fatalf("got %v after %d requests, want %v after one", err, requests.Load(), fixture.want)
			}
		})
	}
}

func TestUnstructuredGatewayOutageIsTransient(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		for _, body := range []string{`<html>Gateway unavailable</html>`, `{"message":"upstream unavailable"}`} {
			t.Run(strconv.Itoa(status)+"/"+strconv.FormatBool(body[0] == '{'), func(t *testing.T) {
				var requests atomic.Int32
				transport := fixtureTransport(t, func(w http.ResponseWriter, _ *http.Request) {
					requests.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					_, _ = io.WriteString(w, body)
				})
				_, err := transport.Post(context.Background(), clientPrefix+"activations/activation/validate", map[string]string{}, false)
				if !errors.Is(err, ErrTransient) || requests.Load() != 1 {
					t.Fatalf("gateway status %d returned %v after %d requests", status, err, requests.Load())
				}
			})
		}
	}
}

func TestTransportRetryLimits(t *testing.T) {
	for _, fixture := range []struct {
		name, retryAfter string
		wantRequests     int32
	}{
		{"attempt_limit", "0", 3},
		{"budget_limit", "30", 1},
		{"overflowing_retry_after", "18446744073709551616", 1},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var requests atomic.Int32
			transport := fixtureTransport(t, func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.Header().Set("Retry-After", fixture.retryAfter)
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"error":{"code":"service_unavailable","message":"Retry","request_id":"request"}}`)
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := transport.Get(ctx, jwksPath)
			if !errors.Is(err, ErrTransient) || requests.Load() != fixture.wantRequests {
				t.Fatalf("got %v after %d requests, want transient after %d", err, requests.Load(), fixture.wantRequests)
			}
			var failure *Error
			if !errors.As(err, &failure) || failure.Code != "service_unavailable" || failure.RequestID != "request" {
				t.Fatal("retry termination lost authoritative HTTP metadata")
			}
		})
	}
}

func TestErrorRequestIDsAreStrictAndRetainedOnHTTPFailures(t *testing.T) {
	for _, fixture := range []struct {
		value any
		valid bool
	}{
		{"A-a_0", true}, {"_", true}, {strings.Repeat("a", 64), true},
		{"", false}, {strings.Repeat("a", 65), false}, {"a b", false}, {"a/b", false},
		{"a\nb", false}, {"é", false}, {nil, false}, {123, false},
	} {
		for _, status := range []int{403, 429, 503} {
			code, kind := "licence_expired", Denied
			if status == 429 {
				code, kind = "rate_limited", Transient
			}
			if status == 503 {
				code, kind = "service_unavailable", Transient
			}
			body, err := json.Marshal(map[string]any{"error": map[string]any{"code": code, "message": "synthetic-secret", "request_id": fixture.value}})
			if err != nil {
				t.Fatal(err)
			}
			var requests atomic.Int32
			transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
				requests.Add(1)
				return testResponse(request, status, string(body)), nil
			})
			_, err = transport.Post(context.Background(), clientPrefix+"sessions", map[string]string{}, false)
			var failure *Error
			if !errors.As(err, &failure) {
				t.Fatal("missing typed failure")
			}
			if fixture.valid {
				if failure.Kind != kind || failure.Code != code || failure.RequestID != fixture.value {
					t.Fatal("HTTP metadata or classification was lost")
				}
			} else if !errors.Is(err, ErrInvalidResponse) || failure.RequestID != "" {
				t.Fatal("malformed request reference was accepted")
			}
			if requests.Load() != 1 || strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("unsafe error handling or unexpected retry")
			}
		}
	}
	failure := classifyTransport(context.DeadlineExceeded)
	var local *Error
	if !errors.As(failure, &local) || !errors.Is(failure, ErrTransient) || local.Code != "" || local.RequestID != "" {
		t.Fatal("local timeout fabricated HTTP metadata")
	}
}

func TestTransportHonorsRetryAfter(t *testing.T) {
	var requests atomic.Int32
	observed := make(chan time.Time, 2)
	transport := fixtureTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		observed <- time.Now()
		if requests.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":{"code":"rate_limited","message":"Retry","request_id":"request"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"keys":[]}`)
	})
	if _, err := transport.Get(context.Background(), jwksPath); err != nil {
		t.Fatal(err)
	}
	first, second := <-observed, <-observed
	if requests.Load() != 2 || second.Sub(first) < time.Second {
		t.Fatalf("Retry-After was ignored: %d requests, interval %v", requests.Load(), second.Sub(first))
	}
}

func TestTransportCancellationStopsRequestAndBackoff(t *testing.T) {
	for _, phase := range []string{"request", "backoff"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			started := make(chan struct{})
			stopped := make(chan struct{})
			var requests atomic.Int32
			transport := fixtureTransport(t, func(w http.ResponseWriter, request *http.Request) {
				if requests.Add(1) != 1 {
					t.Error("cancelled operation was retried")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if phase == "backoff" {
					w.Header().Set("Retry-After", "20")
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = io.WriteString(w, `{"error":{"code":"service_unavailable","message":"Retry","request_id":"request"}}`)
					w.(http.Flusher).Flush()
					close(started)
					close(stopped)
					return
				}
				close(started)
				<-request.Context().Done()
				close(stopped)
			})
			result := make(chan error, 1)
			go func() {
				_, err := transport.Get(ctx, jwksPath)
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not start")
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, ErrCancelled) {
					t.Fatalf("got %v, want cancellation", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("cancellation did not stop the operation")
			}
			select {
			case <-stopped:
			case <-time.After(5 * time.Second):
				t.Fatal("request remained active after cancellation")
			}
			if requests.Load() != 1 {
				t.Fatalf("cancelled operation sent %d requests", requests.Load())
			}
		})
	}
}
