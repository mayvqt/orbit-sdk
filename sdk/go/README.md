# Orbit Go SDK

Add licence activation and feature checks to an installed Go application. The client remembers activation, refreshes access, and restores eligible cached access after a restart. The SDK and examples are [MIT licensed](LICENSE).

## Quick start

To use the SDK from source, add the module to your application's `go.mod` with
a replace path to your SDK checkout:

```go
require github.com/mayvqt/orbit-sdk/sdk/go v0.0.0

replace github.com/mayvqt/orbit-sdk/sdk/go => ../Orbit-SDK/sdk/go
```

Run `go mod tidy` to add the SDK's transitive dependencies to the application module.

Use Go 1.27.1 or newer, then set the public Test app key from **Integration**:

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

`EnsureAccess` calls the prompt only when the installation has no usable access. An outage or a licence without the requested feature never prompts for another key. Call `RequireAccess` before each later protected operation; it checks online when needed. `Snapshot` and `HasFeature` are for display only.

The app key is public configuration, not a secret. Keep licence keys and passwords out of source, command-line arguments and logs; the SDK never saves them. The SDK uses native machine identity automatically when available; see [advanced options](ADVANCED.md#installed-options-and-machine-binding) to disable binding for shared images or supply an application-owned provider.

## Installation state

The state directory is private to the current user: owner-only files on Linux and macOS, and current-user DPAPI on Windows. On macOS 10.12 or newer, builds need cgo and the Xcode Command Line Tools; the installed client links IOKit and CoreFoundation. With `CGO_ENABLED=0`, opening an installed client returns `ErrNativeSupportRequired` instead of falling back to a weaker clock or storage path.

`Options{StatePath: ...}` selects a dedicated absolute directory for a service account or a persistent container volume. Share one `*Client` within a process; another process that opens the same state receives `ErrInstallationInUse`. `Close` stops refresh and saves state without deactivating the licence.

## Application version

Set `Options{AppVersion: "2.4.1"}` so your licence policy can require a minimum
application version and offer updates. Use one to four dot-separated numbers
without leading zeros, optionally followed by a `-pre-release` and `+build`
part, in at most 32 bytes (for example `3.0.0-beta.2+build.5`). `Open` rejects
an invalid value with `ErrConfiguration` and sends a valid one with activation
and validation.

When the policy blocks this version, access checks return an error matching
`ErrAppVersionUnsupported`, and cached or offline access is not used. Ask the
user to update the application; the activation is kept, so the updated version
continues without a new licence key. `Snapshot.UpdateAvailable` contains a
newer version when the policy offers one and is empty otherwise. Every request
also identifies the SDK with an `Orbit-Client` header containing its language,
version and platform.

## Long-term offline files

For an installation that stays disconnected longer than a connected grant allows,
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
sequence-checked, and the SDK saves the signed file before returning access. Reimporting
the same file does not extend its absolute expiry. `RequireAccess` never refreshes or
prompts while a file is active; an expired file returns `offline_file_expired`.

An issued file cannot be revoked while the installation is disconnected. The local
sequence and clock floors prevent ordinary replay and clock rollback, but restoring a
complete old machine or VM snapshot cannot be detected reliably. Explain this limit to
customers before issuing long-term access. See [offline storage details](ADVANCED.md#long-term-offline-files).

## Optional customer accounts

Customer accounts belong to people using your software, separately from your Orbit dashboard account. After a buyer registers and confirms the email link, call `Login`, `OwnedLicences`, and `ActivateAccount`, then use `RequireAccess` before the first protected operation. `EnsureAccess` is for the purchase-key activation flow; it does not perform customer sign-in or licence selection.

Sign-in alone does not grant licensed access. Sessions remain in memory; installed access uses a separate saved credential. See the [console example](../../examples/go/licensed-export/README.md) for registration, recovery, claiming keys and account logout, and [advanced APIs](ADVANCED.md) for explicit storage, custom binding and caller-supplied mutation IDs.

## Floating seats

Floating policies acquire a seat automatically after activation and renew it in
memory. `RequireAccess` checks the current signed interval locally. The snapshot’s `Session`
holds read-only session details. A seat limit, expired seat or temporary outage
does not ask for another licence key.

Call `EndSession(ctx)` when your app becomes idle and `StartSession(ctx)` when it
resumes. Ending clears local access before contacting Orbit and disables automatic
reacquisition. These calls are local no-ops for a confirmed ordinary licence; an
unknown policy is checked online first. Offline-file mode stays offline.

`Close` attempts a bounded seat release while keeping the installation credential.
Restart acquires a fresh seat online. A crash or failed release can occupy the old
seat until its remaining interval expires, at most 120 seconds. An outage permits
only the current verified interval; remote revocation can take effect locally at
that interval's deadline. Session IDs and grants are never restored from disk.

## Licensed updates

```go
update, err := client.CheckForUpdates(ctx, installedReleaseNumber)
if err != nil { return err }
if update != nil {
    authorization, err := client.AuthorizeDownload(ctx, update.Release.ID, update.Artifact.ID)
    if err != nil { return err }
    if err := authorization.Download(ctx, "update.bin", 128*1024*1024); err != nil { return err }
}
```

Use the increasing release number stored with your application, rather than comparing
display versions. Discovery defaults to `stable` and the running supported desktop
target. Pass `UpdateOptions{Channel: "beta", Platform: "linux", Architecture: "arm64"}`
for an explicit target. There is no fallback to another target.

Authorization checks current licence access separately from discovery. Downloading
streams directly from the seller over verified HTTPS, strips bearer credentials on
every redirect, requests identity encoding, and checks the exact length and SHA-256.
The destination appears atomically after verification. Existing files are refused
unless you pass `DownloadOptions{ReplaceExisting: true}`; failures preserve them.
Cancellation removes the temporary file. Nothing executes or unpacks the download.
Keep authorizations in memory and out of logs. A public delivery URL is shareable;
protected seller endpoints must verify the short-lived ticket or broker an expiring
storage URL. See the [seller endpoint example](../../examples/python/seller-downloads/README.md).

## Usage and resources

Configure an `exports` usage limit, then reserve one unit before doing an export:

```go
result, err := client.Consume(ctx, "exports", 1, exportJobID)
if err != nil { return err }
fmt.Println("Remaining exports:", result.Remaining)
// Perform the export and record its result with exportJobID.
```

`Usage(ctx, name)` and `Resources(ctx, name)` read current authoritative counters.
`AcquireResource(ctx, name, resourceID, units, operationID...)` returns an allocation;
release it with `ReleaseResource(ctx, name, allocationID, operationID...)` when the
actual resource is removed. Close, logout and outages do not release resources.

Mutation IDs are optional and generated securely when omitted. Pass a stable job ID
of 16–128 characters for retries across restarts. `*MutationError` retains `OperationID`
and `Uncertain`; retry an uncertain outcome with that same ID and identical input.
Capacity denials expose validated `Usage` or `Resources` counters. Do not retry a
capacity denial using a new ID unless the user intends a new operation.

Usage retries preserve the original debit or denial across period boundaries. Resource
retries preserve allocation identity and charged units but report its current state
and current counter; an old acquire may return `State == "released"`. It never
reactivates that allocation. An export failure does not refund consumed quota.

These calls always require online activation proof and do not acquire floating seats.
Offline files cannot authorize them. `RequireAccess` never consumes units or acquires
resources. Installed software can be modified or bypass reporting: for authoritative
metering, put the capacity check and actual work on your trusted backend.

## Verify seller download tickets

If you serve protected artifacts, verify Orbit's short-lived bearer ticket on your
seller backend before selecting the artifact from your own registry. Configure the
exact HTTPS endpoint and a trusted connected-purpose JWKS; never accept keys or a
destination URL from the ticket. This verifier makes no network request and returns
only the signed artifact metadata.

```go
package main

import (
	"fmt"
	"os"

	orbit "github.com/mayvqt/orbit-sdk/sdk/go"
)

func main() {
	appKey := os.Getenv("ORBIT_APP_KEY")
	ticketToken := os.Getenv("ORBIT_DOWNLOAD_TICKET") // Authorization: Bearer value
	keys, err := os.ReadFile("connected-jwks.json")
	if err != nil { panic(err) }
	verifier, err := orbit.NewDownloadTicketVerifier(appKey, "https://downloads.example.com/artifacts", keys)
	if err != nil { panic(err) }
	ticket, err := verifier.Verify(ticketToken)
	if err != nil { panic(err) }
	// Match all returned metadata against the seller's artifact registry.
	fmt.Printf("licensed artifact %s (%s, %d bytes)\n", ticket.ArtifactID(), ticket.SHA256(), ticket.ByteLength())
}
```

A ticket expires within 120 seconds and can be replayed until then. Treat it
as a secret, never log it, and never use an artifact ID as an unchecked
filesystem path. See [seller download guidance](ADVANCED.md#seller-side-download-tickets).
