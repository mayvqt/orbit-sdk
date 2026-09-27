//go:build orbit_local

package main

import (
	"context"
	orbit "github.com/mayvqt/orbit-sdk/sdk/go"
)

func openClient(ctx context.Context, appKey string, options orbit.Options) (*orbit.Client, error) {
	if _, err := orbit.ParseAppKey(appKey); err == nil {
		return orbit.Open(ctx, appKey, options)
	}
	return orbit.OpenLocal(ctx, appKey, options)
}
