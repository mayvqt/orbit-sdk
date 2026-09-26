# Orbit Go SDK

Add licence activation and feature checks to an installed Go application. The client remembers activation, refreshes access, and restores eligible cached access after a restart. The SDK and examples are [MIT licensed](LICENSE).

## Quick start

The workspace contains an unreleased v0.4.0 candidate. Use the local source checkout
while integrating; there is no v0.4.0 release tag or registry artifact yet. Add the
module to your application's `go.mod` with a replace path to this checkout:

```go
require github.com/mayvqt/orbit-sdk/sdk/go v0.0.0

replace github.com/mayvqt/orbit-sdk/sdk/go => ../Orbit-SDK/sdk/go
```

Run `go mod tidy` to add the SDK's transitive dependencies to the application module.

Set Go 1.27.1 or newer, then paste the public Test app key from **Integration**:

```sh
export ORBIT_APP_KEY='paste the Test app key from Integration'
```

```go
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	orbit "github.com/mayvqt/orbit-sdk/sdk/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	client, err := orbit.Open(ctx, os.Getenv("ORBIT_APP_KEY"))
	if err != nil {
		return err
	}
	defer client.Close()

	input := bufio.NewReader(os.Stdin)
	_, err = client.EnsureAccess(ctx, "export", func(context.Context) (string, error) {
		fmt.Print("Licence key: ")
		line, readErr := input.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return "", readErr
		}
		return strings.TrimSpace(line), nil
	})
	if err != nil {
		return err
	}
	fmt.Println("Export authorized: synthetic report")
	return nil
}
```

`EnsureAccess` calls the prompt only when the installation has no usable access. An outage or a licence without the requested feature never prompts for another key. `RequireAccess` checks online before protected work when needed; `Snapshot` and `HasFeature` are display helpers only.

The app key is public configuration, not a secret. Keep licence keys and passwords out of source, command-line arguments and logs. Orbit never saves them. The SDK automatically uses native machine identity when available; see [advanced options](ADVANCED.md#installed-options-and-machine-binding) to disable binding for shared images or supply an application-owned provider.

The state directory is private to the current user: owner-only files on Linux and macOS, and current-user DPAPI on Windows. On macOS 10.12 or newer, builds need cgo and the Xcode Command Line Tools; the installed client links IOKit and CoreFoundation. With CGO_ENABLED=0, installed-client setup returns ErrNativeSupportRequired rather than using a weaker clock or storage path. The macOS implementation has not yet been validated on native Apple hardware.

`Options{StatePath: ...}` selects a dedicated absolute directory for a service account or persistent container volume. Share one `*Client` in the process; another process opening the same state receives `ErrInstallationInUse`. `Close` stops refresh and saves state without deactivating the licence.

## Long-term offline files

For an installation that will be disconnected longer than a connected grant allows,
ship a trusted offline-purpose JWKS with the application or obtain it from the app-key
origin over verified HTTPS. Configure it when opening the client; never take public
keys from the imported file or from the person who hands you that file:

```go
func runOffline(ctx context.Context, appKey string) error {
	trustedKeys, err := os.ReadFile("trusted-offline-jwks.json")
	if err != nil { return err }
	client, err := orbit.Open(ctx, appKey, orbit.Options{OfflineKeys: trustedKeys})
	if err != nil { return err }
	defer client.Close()

	request, err := client.OfflineRequest()
	if err != nil { return err }
	requestJSON, err := json.MarshalIndent(request, "", "  ")
	if err != nil { return err }
	if err := os.WriteFile("offline-request.json", requestJSON, 0600); err != nil { return err }
	// Transfer this public request to an authorized seller/customer issuance workflow.
	file, err := os.ReadFile("licence.orbit")
	if err != nil { return err }
	if _, err := client.ImportOfflineFile(ctx, file); err != nil { return err }
	if _, err := client.RequireAccess(ctx, "export"); err != nil { return err }
	return nil
}
```

This function uses the same standard-library and `orbit` imports as the Quick start,
plus `encoding/json`.

The request contains the app key and current installation/binding identity, but no
licence key, account session or activation credential. Issuance and renewal happen
through an authorized online workflow; this SDK verifies and imports the resulting
`.orbit` file locally. Imports are signature-, scope-, binding-, expiry- and
sequence-checked, and the signed file is saved before access is returned. Reimporting
the same file does not extend its absolute expiry. `RequireAccess` never refreshes or
prompts while a file is active; an expired file returns `offline_file_expired`.

An already-issued file cannot be promptly revoked while disconnected. The local
sequence and clock floors prevent ordinary replay and clock rollback, but restoring a
complete old machine or VM snapshot cannot be detected reliably. Give this limit to
users before issuing long-term access. See [offline storage details](ADVANCED.md#long-term-offline-files).

## Optional customer accounts

Customer accounts belong to people using your software, separately from your Orbit dashboard account. After a buyer registers and confirms the email link, call `Login`, `OwnedLicences`, and `ActivateAccount`, then use `RequireAccess` before the first protected operation. `EnsureAccess` is for the purchase-key activation flow; it does not perform customer sign-in or licence selection.

Sign-in alone does not grant licensed access. Sessions remain in memory; installed access uses a separate saved credential. See the [console example](../../examples/go/licensed-export/README.md) for registration, recovery, claiming keys and account logout, and [advanced APIs](ADVANCED.md) for explicit storage, custom binding and caller-supplied mutation IDs.
