package orbit

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type unavailableSupportStorage struct{}

func (unavailableSupportStorage) Version() (uint64, error) { panic("support summary read storage") }
func (unavailableSupportStorage) Load() (uint64, *StoredCredential, error) {
	panic("support summary loaded storage")
}
func (unavailableSupportStorage) Save(uint64, StoredCredential) error {
	panic("support summary wrote storage")
}
func (unavailableSupportStorage) Invalidate() (uint64, error) {
	panic("support summary invalidated storage")
}

func TestSupportSummaryIsSafeAndIndependentOfState(t *testing.T) {
	client := &Client{config: Config{ApplicationID: "app", EnvironmentID: "test"}, storage: unavailableSupportStorage{},
		device: Device{InstallationID: "private_installation_1234"},
		state:  accessState{account: &accountSession{token: "synthetic-secret"}}}
	failure := &Error{Kind: Denied, Code: "licence_expired", RequestID: "Req_A-9"}
	client.mu.Lock()
	ready := make(chan SupportSummary, 1)
	go func() { ready <- client.SupportSummary(fmt.Errorf("synthetic-secret: %w", failure)) }()
	var summary SupportSummary
	select {
	case summary = <-ready:
		client.mu.Unlock()
	case <-time.After(time.Second):
		client.mu.Unlock()
		<-ready
		t.Fatal("support summary waited for access state")
	}
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 5 || fields["application_id"] != "app" || fields["environment_id"] != "test" || fields["code"] != "licence_expired" || fields["request_id"] != "Req_A-9" || summary.Timestamp == nil || *summary.Timestamp < 0 {
		t.Fatal("support summary did not contain exactly the public metadata")
	}
	if strings.Contains(string(data), "synthetic-secret") || strings.Contains(string(data), "private_installation") {
		t.Fatal("support summary leaked private state")
	}
	if !errors.Is(failure, ErrDenied) || !errors.Is(failure, &Error{Kind: Denied, Code: "licence_expired", RequestID: "different"}) || errors.Is(failure, &Error{Kind: Denied, Code: "licence_revoked"}) {
		t.Fatal("error matching semantics changed")
	}
	failure.RequestID = "another_reference"
	if *summary.RequestID != "Req_A-9" {
		t.Fatal("summary retained mutable error fields")
	}
	for _, failure := range []*Error{
		{Kind: Denied, Code: "synthetic-secret\n", RequestID: "secret/token"},
		{Kind: Transient, Code: strings.Repeat("a", 129), RequestID: strings.Repeat("a", 65)},
		{Kind: Denied, Code: "é", RequestID: "é"},
		{Kind: Cancelled, Code: "licence_expired", RequestID: "reference"},
		{Kind: ErrorKind("synthetic-secret")}, ErrTransient,
	} {
		summary := client.SupportSummary(failure)
		if !errorCode(summary.Code) || summary.RequestID != nil {
			t.Fatal("caller-created error metadata was not validated")
		}
		for _, value := range []any{failure, *failure} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
				if strings.Contains(fmt.Sprintf(verb, value), "synthetic-secret") || strings.Contains(fmt.Sprintf(verb, value), "secret/token") {
					t.Fatal("error display echoed caller input")
				}
			}
		}
	}
	if summary := client.SupportSummary(ErrTransient); summary.Code != "transient" || summary.RequestID != nil {
		t.Fatal("local failure fabricated HTTP metadata")
	}
	for _, code := range []string{"future_error", strings.Repeat("a", 128)} {
		failure := &Error{Kind: Denied, Code: code}
		if client.SupportSummary(failure).Code != code || failure.Error() != "Orbit denied access. Contact application support." {
			t.Fatal("safe unknown code lost fallback guidance")
		}
	}
}

func TestErrorGuidanceUsesFixedText(t *testing.T) {
	for code, guidance := range map[string]string{
		"invalid_credentials":     "Authenticate again with your licence key or customer account.",
		"session_expired":         "Sign in again to continue.",
		"licence_expired":         "Your licence has expired. Contact application support to renew it.",
		"licence_suspended":       "Your licence is suspended. Contact application support.",
		"licence_revoked":         "Your licence was revoked. Contact application support.",
		"device_limit_reached":    "The device limit is reached. Release an existing device or contact application support.",
		"device_mismatch":         "This device could not be verified. Contact application support.",
		"reset_cooldown":          "Device changes are temporarily limited. Wait before trying again.",
		"application_maintenance": "The application is under maintenance. Try again after maintenance ends.",
	} {
		if (&Error{Kind: Denied, Code: code, RequestID: "reference"}).Error() != guidance {
			t.Fatalf("unexpected guidance for %s", code)
		}
	}
}
