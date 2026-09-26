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

The state directory is private to the current user: owner-only files on Linux and current-user DPAPI on Windows. `Options{StatePath: ...}` selects a dedicated absolute directory for a service account or persistent container volume. Share one `*Client` in the process; another process opening the same state receives `ErrInstallationInUse`. `Close` stops refresh and saves state without deactivating the licence.

## Optional customer accounts

Customer accounts belong to people using your software, separately from your Orbit dashboard account. After a buyer registers and confirms the email link, call `Login`, `OwnedLicences`, and `ActivateAccount`, then use `RequireAccess` before the first protected operation. `EnsureAccess` is for the purchase-key activation flow; it does not perform customer sign-in or licence selection.

Sign-in alone does not grant licensed access. Sessions remain in memory; installed access uses a separate saved credential. See the [console example](../../examples/go/licensed-export/README.md) for registration, recovery, claiming keys and account logout, and [advanced APIs](ADVANCED.md) for explicit storage, custom binding and caller-supplied mutation IDs.
