package orbit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"weak"
)

// BindingMode selects how an installed client identifies this machine.
type BindingMode uint8

const (
	BindingAutomatic BindingMode = iota
	BindingDisabled
	BindingCustom
)

// Options contains optional installed-client settings. The zero value uses
// native machine_v1 identity when available and the platform's default state path.
type Options struct {
	StatePath           string
	BindingMode         BindingMode
	Fingerprint         string
	FingerprintProvider string
}

func resolveBinding(key AppKey, options Options) (*string, *string, error) {
	if options.BindingMode > BindingCustom {
		return nil, nil, ErrConfiguration
	}
	switch options.BindingMode {
	case BindingAutomatic:
		if options.Fingerprint != "" || options.FingerprintProvider != "" {
			return nil, nil, ErrConfiguration
		}
		fingerprint, err := NativeFingerprint(key.applicationID, key.environmentID)
		if err != nil {
			var failure *Error
			if errors.As(err, &failure) && failure.Kind == Denied && failure.Code == "device_identity_unavailable" {
				return nil, nil, nil
			}
			return nil, nil, err
		}
		provider := "machine_v1"
		return &fingerprint, &provider, nil
	case BindingDisabled:
		if options.Fingerprint != "" || options.FingerprintProvider != "" {
			return nil, nil, ErrConfiguration
		}
		return nil, nil, nil
	case BindingCustom:
		if !lowerHex(options.Fingerprint, 64) || !strings.HasPrefix(options.FingerprintProvider, "custom:") || !validProvider(options.FingerprintProvider) {
			return nil, nil, ErrConfiguration
		}
		fingerprint, provider := options.Fingerprint, options.FingerprintProvider
		return &fingerprint, &provider, nil
	default:
		return nil, nil, ErrConfiguration
	}
}

type installedLifecycle struct {
	context        context.Context
	cancel         context.CancelFunc
	done           chan struct{}
	wake           chan struct{}
	cleanup        runtime.Cleanup
	closeOnce      sync.Once
	closeErr       error
	restoring      bool
	lastCheckpoint time.Time // Protected by Client.mu.
}

// Open restores a stable installation, checks its credential online when present,
// and starts automatic refresh. Only a recognized outage allows verified cached
// offline access. New installations do not contact Orbit until activation.
func Open(ctx context.Context, rawAppKey string, options ...Options) (*Client, error) {
	if len(options) > 1 {
		return nil, ErrConfiguration
	}
	var config Options
	if len(options) == 1 {
		config = options[0]
	}
	key, err := ParseAppKey(rawAppKey)
	if err != nil {
		return nil, err
	}
	transport, err := NewTransport(key.apiOrigin)
	if err != nil {
		return nil, err
	}
	client, err := openInstalled(ctx, key, config, transport)
	if err != nil {
		transport.CloseIdleConnections()
	}
	return client, err
}

func openInstalled(ctx context.Context, key AppKey, options Options, transport *Transport) (*Client, error) {
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	fingerprint, fingerprintProvider, err := resolveBinding(key, options)
	if err != nil {
		return nil, err
	}
	// The transport has already rejected paths, queries, credentials and insecure
	// origins. Normalize equivalent DNS case, default port and trailing slash.
	host := strings.ToLower(transport.base.Hostname())
	port := transport.base.Port()
	if port == "443" && transport.base.Scheme == "https" {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	origin := transport.base.Scheme + "://" + host
	scope := installedScope{APIOrigin: origin, Issuer: key.issuer, ApplicationID: key.applicationID, EnvironmentID: key.environmentID}
	scopeBytes, _ := json.Marshal(scope)
	digest := sha256.Sum256(scopeBytes)
	path := options.StatePath
	if path == "" {
		base := ""
		switch runtime.GOOS {
		case "linux":
			base = os.Getenv("XDG_STATE_HOME")
			if base == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return nil, ErrStorage
				}
				base = filepath.Join(home, ".local", "state")
			}
			base = filepath.Join(base, "orbit")
		case "windows":
			base = filepath.Join(os.Getenv("LOCALAPPDATA"), "Orbit")
		default:
			return nil, ErrStorage
		}
		if !filepath.IsAbs(base) {
			return nil, ErrConfiguration
		}
		path = filepath.Join(base, hex.EncodeToString(digest[:]))
	}
	if !filepath.IsAbs(path) {
		return nil, ErrConfiguration
	}
	files, provider, created, err := openInstalledFiles(path, digest[:])
	if err != nil {
		return nil, err
	}
	storage := &installedStorage{files: files}
	data, err := files.read()
	if errors.Is(err, errStorageMissing) && created {
		device, e := NewInstallation()
		if e != nil {
			files.close()
			return nil, e
		}
		record := installedRecord{SDK: installedSDK, Format: 2, Provider: provider, Scope: scope, Installation: installedIdentity{ID: device.InstallationID, Fingerprint: cloneString(fingerprint), FingerprintProvider: cloneString(fingerprintProvider)}}
		err = storage.writeLocked(record)
	} else if err == nil {
		storage.record, err = decodeInstalled(data, scope, provider)
	}
	clear(data)
	if err != nil {
		files.close()
		return nil, ErrStorage
	}
	if !created {
		if _, err = storage.rebindIfChanged(fingerprint, fingerprintProvider); err != nil {
			files.close()
			return nil, err
		}
	}
	record := storage.record
	device := Device{InstallationID: record.Installation.ID, Fingerprint: fingerprint, FingerprintProvider: fingerprintProvider}
	client, err := newClientWithStorage(key, device, transport, storage, true)
	if err != nil {
		storage.close()
		return nil, err
	}
	lifetime, cancel := context.WithCancel(context.Background())
	transport.installationLifetime = lifetime
	client.installed = storage
	client.lifecycle = &installedLifecycle{context: lifetime, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1), lastCheckpoint: time.Now()}
	client.storageCapability = StorageOperatingSystemProtected
	if provider == "private_file" {
		client.storageCapability = StoragePrivateFile
	}
	// A cached anchor is not online evidence. Restoration is private until the
	// bounded validation attempt returns a qualifying transient failure.
	if err := client.restoreInstalled(record); err != nil {
		cancel()
		storage.close()
		transport.CloseIdleConnections()
		return nil, err
	}
	if record.Credential != nil {
		_, err = client.Refresh(ctx)
		if err != nil && !errors.Is(err, ErrTransient) {
			cancel()
			storage.close()
			transport.CloseIdleConnections()
			return nil, err
		}
	}
	go runInstalled(weak.Make(client), client.lifecycle)
	client.lifecycle.cleanup = runtime.AddCleanup(client, func(resources installedCleanup) {
		resources.lifecycle.cancel()
		<-resources.lifecycle.done
		_ = resources.storage.close()
		resources.transport.CloseIdleConnections()
	}, installedCleanup{client.lifecycle, storage, transport})
	return client, nil
}

func (c *Client) restoreInstalled(record installedRecord) (err error) {
	a, credential := record.Access, record.storedCredential()
	if a == nil || credential == nil {
		return nil
	}
	if !equalString(record.Installation.Fingerprint, c.device.Fingerprint) || !equalString(record.Installation.FingerprintProvider, c.device.FingerprintProvider) {
		// A cache belongs to the exact machine identity saved with it. Keep the
		// encrypted record intact for recovery, but force online validation.
		return nil
	}
	restored := false
	defer func() {
		if !restored {
			err = c.installed.dropCache()
		}
	}()
	keys, err := parseKeys(a.JWKS)
	if err != nil {
		return nil
	}
	expected := expectedGrant{issuer: c.key.issuer, application: c.key.applicationID, environment: c.key.environmentID, licence: credential.LicenceID, activation: credential.ActivationID, installation: c.device.InstallationID, fingerprint: c.device.Fingerprint, fingerprintProvider: c.device.FingerprintProvider, allowUnboundFingerprint: true, credentialExpiresAt: credential.CredentialExpiresAt, credentialPersistent: credential.CredentialExpiresAt == 0, licenceExpiresAt: a.LicenceExpiresAt, now: a.ReceivedServerTime}
	claims, err := verifyGrant(a.JWS, keys, expected)
	if err != nil {
		return nil
	}
	start, err := captureStart()
	if err != nil || start.wall < a.WallHighWater || a.ServerHighWater < a.ReceivedServerTime || a.WallHighWater < a.ReceivedWallTime {
		return nil
	}
	serverProgress, wallProgress := a.ServerHighWater-a.ReceivedServerTime, a.WallHighWater-a.ReceivedWallTime
	if serverProgress-wallProgress < -30 || serverProgress-wallProgress > 30 {
		return nil
	}
	elapsed := start.wall - a.ReceivedWallTime
	if elapsed < 0 || a.ReceivedServerTime > 253402300799-elapsed {
		return nil
	}
	estimated := a.ReceivedServerTime + elapsed
	if estimated < a.ServerHighWater {
		estimated = a.ServerHighWater
	}
	if estimated < claims.NotBefore || estimated >= claims.ExpiresAt || credential.CredentialExpiresAt != 0 && estimated >= credential.CredentialExpiresAt {
		return nil
	}
	c.keys = keys
	c.state.claims = claims
	c.state.anchor = &timeAnchor{server: estimated, requestStart: start}
	c.state.transient = true
	c.lifecycle.restoring = true
	restored = true
	return nil
}

func (c *Client) operationContext(ctx context.Context) (context.Context, func()) {
	if c.lifecycle == nil {
		return ctx, func() {}
	}
	child, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.lifecycle.context, cancel)
	if c.lifecycle.context.Err() != nil {
		cancel()
	}
	return child, func() { stop(); cancel() }
}
func (c *Client) checkpointLocked(force bool) error {
	if c.installed == nil || c.state.anchor == nil || c.state.claims == nil {
		return nil
	}
	if !force && time.Since(c.lifecycle.lastCheckpoint) < time.Minute {
		return nil
	}
	now, err := c.state.anchor.now()
	if err != nil {
		c.state.claims, c.state.anchor = nil, nil
		if storeErr := c.installed.dropCache(); storeErr != nil {
			return storeErr
		}
		return err
	}
	if err := c.installed.checkpoint(now, time.Now().Unix()); err != nil {
		c.state.claims, c.state.anchor = nil, nil
		if errors.Is(err, ErrClockUncertain) {
			if dropErr := c.installed.dropCache(); dropErr != nil {
				return dropErr
			}
		}
		return err
	}
	c.lifecycle.lastCheckpoint = time.Now()
	return nil
}

type installedCleanup struct {
	lifecycle *installedLifecycle
	storage   *installedStorage
	transport *Transport
}

func (c *Client) wakeInstalled() {
	if c.lifecycle != nil {
		select {
		case c.lifecycle.wake <- struct{}{}:
		default:
		}
	}
}
func runInstalled(reference weak.Pointer[Client], lifecycle *installedLifecycle) {
	defer close(lifecycle.done)
	timer := time.NewTimer(0)
	defer timer.Stop()
	var timerC <-chan time.Time = timer.C
	for {
		select {
		case <-lifecycle.context.Done():
			return
		case <-lifecycle.wake:
		case <-timerC:
		}
		alive, delay := installedTick(reference)
		if !alive {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
		if delay >= 0 {
			if delay < 10*time.Millisecond {
				delay = 10 * time.Millisecond
			}
			timer.Reset(delay)
			timerC = timer.C
		}
	}
}

// The worker holds no strong Client reference while waiting. A runtime cleanup
// releases abandoned resources; orderly Close additionally saves clock evidence.
func installedTick(reference weak.Pointer[Client]) (bool, time.Duration) {
	c := reference.Value()
	if c == nil {
		return false, 0
	}
	c.mu.Lock()
	if c.syncStorageLocked() != nil {
		c.mu.Unlock()
		return true, -1
	}
	_ = c.checkpointLocked(false)
	snapshot := c.snapshotLocked()
	due := c.state.credential != nil && (snapshot.Access == AccessRefreshRequired || snapshot.Access == AccessExpired || snapshot.Access == AccessOffline) && !time.Now().Before(c.state.retryAt)
	c.mu.Unlock()
	if due {
		_, _ = c.refresh(c.lifecycle.context, true)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.state.credential == nil {
		return true, -1
	}
	delay := time.Until(c.state.retryAt)
	if c.state.retryAt.IsZero() || delay <= 0 {
		delay = time.Second
		if c.state.anchor != nil && c.state.claims != nil {
			if now, err := c.state.anchor.now(); err == nil && c.state.claims.RefreshAfter > now {
				delay = time.Duration(c.state.claims.RefreshAfter-now) * time.Second
			}
		}
	}
	if c.state.anchor != nil && c.state.claims != nil {
		checkpoint := time.Until(c.lifecycle.lastCheckpoint.Add(time.Minute))
		if checkpoint < delay {
			delay = checkpoint
		}
	}
	return true, delay
}

// Close cancels and joins owned refresh work, checkpoints clock evidence and
// releases the exclusive installation lease. It never deactivates the licence.
func (c *Client) Close() error {
	if c.lifecycle == nil {
		c.transport.CloseIdleConnections()
		return nil
	}
	c.lifecycle.closeOnce.Do(func() {
		c.lifecycle.cleanup.Stop()
		c.lifecycle.cancel()
		<-c.lifecycle.done
		// Join the serialized engine after cancellation; late replies cannot commit.
		c.serial <- struct{}{}
		c.mu.Lock()
		c.lifecycle.closeErr = c.checkpointLocked(true)
		c.closed = true
		clearState(&c.state)
		c.mu.Unlock()
		c.unlockOperation()
		c.transport.settleInstalledRequests()
		if err := c.installed.close(); c.lifecycle.closeErr == nil {
			c.lifecycle.closeErr = err
		}
		c.transport.CloseIdleConnections()
	})
	return c.lifecycle.closeErr
}
