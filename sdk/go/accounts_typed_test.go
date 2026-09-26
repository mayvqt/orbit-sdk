package orbit

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestOwnedLicenceUsesNativeTimeAndDurationTypes(t *testing.T) {
	var licence OwnedLicence
	data := json.RawMessage(`{"id":"licence_1","policy_name":"Annual","state":"active","expiry_mode":"duration","first_used_at":"2030-01-02T03:04:05Z","expires_at":"2031-01-02T03:04:05Z","duration_seconds":31536000,"device_limit":2,"hwid_locked":false,"offline_allowed":true,"offline_seconds":900,"offline_file_seconds":86400,"entitlements":{"export":true}}`)
	if err := decodeJSON(data, &licence); err != nil {
		t.Fatal(err)
	}
	if err := checkLicence(licence); err != nil || licence.FirstUsedAt == nil || !licence.FirstUsedAt.Equal(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)) || licence.ExpiresAt == nil || !licence.ExpiresAt.Equal(time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)) || licence.Duration == nil || *licence.Duration != 365*24*time.Hour || licence.OfflineDuration != 15*time.Minute || licence.OfflineFileDuration != 24*time.Hour {
		t.Fatalf("native account and licence types were not decoded: %+v, %v", licence, err)
	}
	var page OwnedLicences
	if err := decodeJSON([]byte(fmt.Sprintf(`{"items":[%s],"next_cursor":null}`, data)), &page); err != nil || len(page.Items) != 1 || page.Items[0].OfflineFileDuration != 24*time.Hour {
		t.Fatalf("owned-licence page omitted the typed offline file duration: %+v, %v", page, err)
	}
	if err := json.Unmarshal([]byte(`{"duration_seconds":9223372036854776}`), &licence); err == nil {
		t.Fatal("overflowing duration was accepted")
	}
}

func TestOwnedLicenceStrictWireShape(t *testing.T) {
	valid := `{"id":"licence_1","policy_name":"Annual","state":"active","expiry_mode":"duration","first_used_at":null,"expires_at":null,"duration_seconds":null,"device_limit":1,"hwid_locked":false,"offline_allowed":false,"offline_seconds":0,"offline_file_seconds":0,"entitlements":{"export":true}}`
	invalid := []string{
		strings.Replace(valid, `"state":"active",`, "", 1),
		strings.Replace(valid, `"state":"active"`, `"state":null`, 1),
		strings.Replace(valid, `"offline_allowed":false`, `"offline_allowed":null`, 1),
		strings.Replace(valid, `"policy_name":"Annual"`, `"policy_name":null`, 1),
		strings.Replace(valid, `"entitlements":{"export":true}`, `"entitlements":null`, 1),
		strings.Replace(valid, `"state":"active"`, `"State":"active"`, 1),
		strings.Replace(valid, `"offline_allowed":false`, `"Offline_Allowed":false`, 1),
		strings.Replace(valid, `"policy_name":"Annual"`, `"Policy_Name":"Annual"`, 1),
		strings.Replace(valid, `"entitlements":{"export":true}`, `"Entitlements":{"export":true}`, 1),
		strings.Replace(valid, `,"offline_file_seconds":0`, "", 1),
	}
	for i, raw := range invalid {
		var licence OwnedLicence
		if err := json.Unmarshal([]byte(raw), &licence); err == nil {
			t.Errorf("invalid owned-licence wire shape %d accepted", i)
		}
	}
}

func TestOwnedLicenceBoundaryDatesAndDurations(t *testing.T) {
	var licence OwnedLicence
	const maxDurationSeconds = 9223372036
	raw := `{"id":"licence_1","policy_name":"Annual","state":"active","expiry_mode":"duration","first_used_at":"1969-12-31T23:59:59Z","expires_at":"9999-12-31T23:59:59Z","duration_seconds":9223372036,"device_limit":1,"hwid_locked":false,"offline_allowed":true,"offline_seconds":9223372036,"offline_file_seconds":31622400,"entitlements":{"export":true}}`
	if err := json.Unmarshal([]byte(raw), &licence); err != nil {
		t.Fatal(err)
	}
	const maxDuration = time.Duration(maxDurationSeconds) * time.Second
	if licence.FirstUsedAt == nil || !licence.FirstUsedAt.Equal(time.Unix(-1, 0).UTC()) || licence.ExpiresAt == nil || licence.Duration == nil || *licence.Duration != maxDuration || licence.OfflineDuration != maxDuration {
		t.Fatalf("boundary native types were not retained: %+v", licence)
	}
	if err := json.Unmarshal([]byte(strings.Replace(raw, `"offline_seconds":9223372036`, `"offline_seconds":-1`, 1)), &licence); err == nil {
		t.Fatal("negative offline duration was accepted")
	}
	for _, seconds := range []string{"-1", "1", "86399", "31622401", "1.5", "null"} {
		invalid := strings.Replace(raw, `"offline_file_seconds":31622400`, `"offline_file_seconds":`+seconds, 1)
		if err := json.Unmarshal([]byte(invalid), &licence); err == nil {
			t.Fatalf("invalid offline file duration accepted: %s", seconds)
		}
	}
}
