package orbit

// Setup contains the public values needed to create an installed client.
// InstallationID must be persisted by the host and reused across launches.
type Setup struct {
	APIOrigin      string
	ApplicationID  string
	EnvironmentID  string
	Issuer         string
	InstallationID string
}

// Connect creates an unbound client using the production HTTPS transport and
// in-memory credential storage. It does not activate a licence or make a
// network request.
func Connect(setup Setup) (*Client, error) {
	transport, err := NewTransport(setup.APIOrigin)
	if err != nil {
		return nil, err
	}
	client, err := NewClient(
		Config{ApplicationID: setup.ApplicationID, EnvironmentID: setup.EnvironmentID, Issuer: setup.Issuer},
		Device{InstallationID: setup.InstallationID},
		transport,
	)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	return client, nil
}
