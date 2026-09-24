//go:build orbit_local

package main

import (
	"strings"

	orbit "github.com/mayvqt/orbit-sdk/sdk/go"
)

func newTransport(origin string) (*orbit.Transport, error) {
	if strings.HasPrefix(origin, "http:") {
		return orbit.NewLocalTransport(origin)
	}
	return orbit.NewTransport(origin)
}
