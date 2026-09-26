//go:build !orbit_local

package main

import (
	"context"
	orbit "github.com/mayvqt/orbit-sdk/sdk/go"
)

func openClient(ctx context.Context, config orbit.AppConfig) (*orbit.Client, error) {
	return orbit.Open(ctx, config)
}
