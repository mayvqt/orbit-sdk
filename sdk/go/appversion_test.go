package orbit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

type appVersionVectors struct {
	AppVersions []struct {
		Value string `json:"value"`
		Valid bool   `json:"valid"`
	} `json:"app_versions"`
	ClientHeaders []struct {
		Language   string  `json:"language"`
		SDKVersion string  `json:"sdk_version"`
		Platform   string  `json:"platform"`
		Header     *string `json:"header"`
	} `json:"client_headers"`
	UpdateAvailable []struct {
		Name    string          `json:"name"`
		Value   json.RawMessage `json:"value"`
		Valid   bool            `json:"valid"`
		Version *string         `json:"version"`
	} `json:"update_available"`
}

func loadAppVersionVectors(t *testing.T) appVersionVectors {
	t.Helper()
	data, err := os.ReadFile("../../contracts/sdk/app-versions.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors appVersionVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func TestAppVersionGrammarVectors(t *testing.T) {
	for _, item := range loadAppVersionVectors(t).AppVersions {
		if validAppVersion(item.Value) != item.Valid {
			t.Errorf("%q: valid=%v", item.Value, !item.Valid)
		}
	}
}

func TestClientHeaderVectors(t *testing.T) {
	for _, item := range loadAppVersionVectors(t).ClientHeaders {
		header, ok := formatClientHeader(item.Language, item.SDKVersion, item.Platform)
		if ok != (item.Header != nil) || item.Header != nil && header != *item.Header {
			t.Errorf("%+v: got %q, %v", item, header, ok)
		}
	}
	prefix, platform, found := strings.Cut(clientHeader, " (")
	if !found || !strings.HasPrefix(prefix, "go/") {
		t.Fatalf("unexpected header %q", clientHeader)
	}
	if header, ok := formatClientHeader("go", strings.TrimPrefix(prefix, "go/"), strings.TrimSuffix(platform, ")")); !ok || header != clientHeader {
		t.Fatalf("header %q does not match the grammar", clientHeader)
	}
	info, _ := debug.ReadBuildInfo()
	if info != nil && info.Main.Path == modulePath && info.Main.Version == "(devel)" && prefix != "go/0.0.0" {
		t.Fatalf("source build header %q", clientHeader)
	}
}

func TestUpdateHintVectors(t *testing.T) {
	for _, item := range loadAppVersionVectors(t).UpdateAvailable {
		reply := `{"activation_id":"activation"}`
		if item.Value != nil {
			reply = `{"activation_id":"activation","update_available":` + string(item.Value) + `}`
		}
		version, err := updateHint(json.RawMessage(reply))
		if !item.Valid {
			if !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("%s: accepted %q", item.Name, version)
			}
			continue
		}
		want := ""
		if item.Version != nil {
			want = *item.Version
		}
		if err != nil || version != want {
			t.Errorf("%s: got %q, %v", item.Name, version, err)
		}
	}
}

func TestAppVersionIsSentAndUnsupportedVersionDeniesWithoutFallback(t *testing.T) {
	f := newInstalledFixture(t, true)
	path := filepath.Join(installedTestTempDir(t), "state")
	options := installedOptions(path)
	options.AppVersion = "01"
	if _, err := f.openWith(path, options); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("invalid application version opened: %v", err)
	}
	options.AppVersion = "2.4.1-beta.2"
	client, err := f.openWith(path, options)
	if err != nil {
		t.Fatal(err)
	}
	f.updateAvailable = map[string]any{"version": "2.5.0"}
	snapshot, err := client.Activate(context.Background(), "synthetic-key")
	if err != nil || snapshot.UpdateAvailable != "2.5.0" {
		t.Fatalf("activation: %+v, %v", snapshot, err)
	}
	if f.lastBody["app_version"] != "2.4.1-beta.2" {
		t.Fatalf("activation body: %v", f.lastBody)
	}
	for _, header := range f.clientHeaders {
		if header != clientHeader {
			t.Fatalf("request header %q", header)
		}
	}

	f.mode.Store(6)
	validations := f.validation.Load()
	_, err = client.Refresh(context.Background())
	var failure *Error
	if !errors.Is(err, ErrAppVersionUnsupported) || !errors.As(err, &failure) || failure.RequestID != "fixture" {
		t.Fatalf("validation: %v", err)
	}
	if f.validation.Load() != validations+1 || f.lastBody["app_version"] != "2.4.1-beta.2" {
		t.Fatalf("denial retried or body missing app_version: %d, %v", f.validation.Load()-validations, f.lastBody)
	}
	snapshot, err = client.Snapshot()
	if err != nil || snapshot.Access != AccessRefreshRequired || snapshot.HasFeature("export") || snapshot.UpdateAvailable != "" {
		t.Fatalf("denial kept cached or offline access: %+v, %v", snapshot, err)
	}
	prompted := false
	_, err = client.EnsureAccess(context.Background(), "export", func(context.Context) (string, error) {
		prompted = true
		return "replacement-key", nil
	})
	if !errors.Is(err, ErrAppVersionUnsupported) || prompted || f.validation.Load() != validations+1 {
		t.Fatalf("paced access check: %v, prompted=%v", err, prompted)
	}
	if client.installed.record.Credential == nil || client.installed.record.Access != nil {
		t.Fatal("denial must keep the activation and drop cached access")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	client, err = f.openWith(path, options)
	if err != nil {
		t.Fatalf("reopen after denial: %v", err)
	}
	defer client.Close()
	if _, err := client.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrAppVersionUnsupported) {
		t.Fatalf("reopened access: %v", err)
	}
}
