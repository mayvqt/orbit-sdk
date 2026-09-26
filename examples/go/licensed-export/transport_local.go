//go:build orbit_local

package main

import (
	"context"
	orbit "github.com/mayvqt/orbit-sdk/sdk/go"
	"strings"
)

func openClient(ctx context.Context, config orbit.AppConfig) (*orbit.Client, error) {
	if strings.HasPrefix(config.APIOrigin, "http:") {
		return orbit.OpenLocal(ctx, config)
	}
	return orbit.Open(ctx, config)
}
