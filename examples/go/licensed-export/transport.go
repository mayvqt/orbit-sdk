//go:build !orbit_local

package main

import orbit "github.com/mayvqt/orbit-sdk/sdk/go"

func newTransport(origin string) (*orbit.Transport, error) { return orbit.NewTransport(origin) }
