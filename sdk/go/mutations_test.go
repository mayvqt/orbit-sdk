package orbit

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestExplicitEmptyOrInvalidMutationIDsFailBeforeStateOrNetwork(t *testing.T) {
	var requests atomic.Int32
	transport := testTransport(t, func(request *http.Request) (*http.Response, error) {
		requests.Add(1)
		return testResponse(request, http.StatusOK, `{}`), nil
	})
	storage := &MemoryStorage{}
	client, err := NewClientWithStorage(testAppKey(), Device{InstallationID: "installation_1234"}, transport, storage)
	if err != nil {
		t.Fatal(err)
	}
	version, err := storage.Version()
	if err != nil {
		t.Fatal(err)
	}
	invalidIDs := []string{"", strings.Repeat("x", 15), strings.Repeat("\xff", 16)}
	for _, id := range invalidIDs {
		operations := []struct {
			name string
			call func() error
		}{
			{"key activation", func() error { _, e := client.Activate(context.Background(), "key", id); return e }},
			{"key activation with previous", func() error { _, e := client.ActivateWithPrevious(context.Background(), "key", "", id); return e }},
			{"account activation", func() error { _, e := client.ActivateAccount(context.Background(), "licence", id); return e }},
			{"account activation with previous", func() error {
				_, e := client.ActivateAccountWithPrevious(context.Background(), "licence", "", id)
				return e
			}},
			{"claim", func() error { _, e := client.ClaimLicence(context.Background(), "key", id); return e }},
			{"deactivation", func() error { return client.Deactivate(context.Background(), id) }},
		}
		for _, operation := range operations {
			t.Run(operation.name+"/"+id, func(t *testing.T) {
				if err := operation.call(); !errors.Is(err, ErrConfiguration) {
					t.Fatalf("explicit invalid operation ID returned %v", err)
				}
			})
		}
	}
	after, err := storage.Version()
	if err != nil || after != version || requests.Load() != 0 {
		t.Fatalf("invalid IDs changed state or used network: version=%d->%d requests=%d err=%v", version, after, requests.Load(), err)
	}
}
