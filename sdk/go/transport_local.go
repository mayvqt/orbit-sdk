//go:build orbit_local

package orbit

// NewLocalTransport explicitly enables HTTP for a literal loopback IP only.
// It is absent from default builds and never uses an environment proxy.
func NewLocalTransport(base string) (*Transport, error) { return newTransport(base, "http", true) }
