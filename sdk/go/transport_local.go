//go:build orbit_local

package orbit

import "context"

// NewLocalTransport explicitly enables HTTP for a literal loopback IP only.
// It is absent from default builds and never uses an environment proxy.
func NewLocalTransport(base string) (*Transport, error) { return newTransport(base, "http", true) }

// OpenLocal is the installed client for an explicitly enabled loopback test server.
// It retains the same persistence, verification and refresh behavior as Open.
func OpenLocal(ctx context.Context, rawAppKey string, options ...Options) (*Client, error) {
	if len(options) > 1 {
		return nil, ErrConfiguration
	}
	var config Options
	if len(options) == 1 {
		config = options[0]
	}
	key, err := parseAppKey(rawAppKey, "http", true)
	if err != nil {
		return nil, err
	}
	transport, err := NewLocalTransport(key.apiOrigin)
	if err != nil {
		return nil, err
	}
	client, err := openInstalled(ctx, key, config, transport)
	if err != nil {
		transport.CloseIdleConnections()
	}
	return client, err
}
