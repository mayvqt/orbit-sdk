package orbit

import (
	"strings"
	"unicode/utf8"
)

// Environment identifies whether an app key targets Orbit's test or live
// environment.
type Environment string

const (
	EnvironmentTest Environment = "test"
	EnvironmentLive Environment = "live"
)

// AppKey holds the parsed public app key copied from Orbit's Integration page:
// the API origin, application and environment. An app key is not a secret.
// Construct it with ParseAppKey.
type AppKey struct {
	apiOrigin     string
	issuer        string
	applicationID string
	environmentID string
	environment   Environment
}

func (k AppKey) APIOrigin() string        { return k.apiOrigin }
func (k AppKey) Issuer() string           { return k.issuer }
func (k AppKey) ApplicationID() string    { return k.applicationID }
func (k AppKey) EnvironmentID() string    { return k.environmentID }
func (k AppKey) Environment() Environment { return k.environment }

const appKeyMaxLength = 512
const appKeyTestPrefix = "orbit_app_test_"
const appKeyLivePrefix = "orbit_app_live_"

// ParseAppKey parses the public app key shown on Orbit's Integration page.
// Any other input returns ErrConfiguration.
func ParseAppKey(raw string) (AppKey, error) { return parseAppKey(raw, "https", false) }

// parseAppKey additionally accepts an explicit http loopback origin for the
// local-development entry point only; ParseAppKey never relaxes this.
func parseAppKey(raw, scheme string, local bool) (AppKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > appKeyMaxLength {
		return AppKey{}, ErrConfiguration
	}
	var environment Environment
	var rest string
	switch {
	case strings.HasPrefix(trimmed, appKeyTestPrefix):
		environment, rest = EnvironmentTest, trimmed[len(appKeyTestPrefix):]
	case strings.HasPrefix(trimmed, appKeyLivePrefix):
		environment, rest = EnvironmentLive, trimmed[len(appKeyLivePrefix):]
	default:
		return AppKey{}, ErrConfiguration
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 3 {
		return AppKey{}, ErrConfiguration
	}
	originBytes, err := canonicalBase64(parts[0])
	if err != nil || !utf8.Valid(originBytes) {
		return AppKey{}, ErrConfiguration
	}
	origin := string(originBytes)
	parsed, err := validateOrigin(origin, scheme, local)
	if err != nil || origin != parsed.Scheme+"://"+parsed.Host {
		return AppKey{}, ErrConfiguration
	}
	applicationID, environmentID := parts[1], parts[2]
	if !opaque(applicationID) || !opaque(environmentID) {
		return AppKey{}, ErrConfiguration
	}
	return AppKey{apiOrigin: origin, issuer: origin, applicationID: applicationID, environmentID: environmentID, environment: environment}, nil
}
