package orbit

import (
	"errors"
	"testing"
)

func TestConnectCreatesUnboundClient(t *testing.T) {
	setup := Setup{
		APIOrigin:      "https://orbit.example.test/",
		ApplicationID:  "app",
		EnvironmentID:  "test",
		Issuer:         "https://issuer.example.test",
		InstallationID: "installation_1234",
	}
	client, err := Connect(setup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.transport.CloseIdleConnections)
	if client.config != (Config{ApplicationID: setup.ApplicationID, EnvironmentID: setup.EnvironmentID, Issuer: setup.Issuer}) {
		t.Fatal("client configuration did not match setup")
	}
	if client.device.InstallationID != setup.InstallationID || client.device.Fingerprint != nil || client.device.FingerprintProvider != nil {
		t.Fatal("client did not use the unbound installation device")
	}
	if client.transport.base.String() != "https://orbit.example.test/" {
		t.Fatalf("unexpected transport origin: %s", client.transport.base)
	}
	if client.storageCapability != StorageMemoryOnly || client.state.credential != nil {
		t.Fatal("setup unexpectedly loaded or persisted activation state")
	}
}

func TestConnectRejectsInvalidOriginAndScope(t *testing.T) {
	valid := Setup{
		APIOrigin:      "https://orbit.example.test",
		ApplicationID:  "app",
		EnvironmentID:  "test",
		Issuer:         "https://issuer.example.test",
		InstallationID: "installation_1234",
	}
	tests := map[string]func(*Setup){
		"http origin":        func(s *Setup) { s.APIOrigin = "http://orbit.example.test" },
		"origin path":        func(s *Setup) { s.APIOrigin = "https://orbit.example.test/api" },
		"origin query":       func(s *Setup) { s.APIOrigin = "https://orbit.example.test?tenant=one" },
		"origin credentials": func(s *Setup) { s.APIOrigin = "https://user@orbit.example.test" },
		"application":        func(s *Setup) { s.ApplicationID = "bad id" },
		"environment":        func(s *Setup) { s.EnvironmentID = "" },
		"issuer":             func(s *Setup) { s.Issuer = "" },
		"installation":       func(s *Setup) { s.InstallationID = "short" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			setup := valid
			change(&setup)
			client, err := Connect(setup)
			if client != nil || !errors.Is(err, ErrConfiguration) {
				t.Fatalf("Connect() = (%v, %v), want (nil, ErrConfiguration)", client, err)
			}
		})
	}
}
