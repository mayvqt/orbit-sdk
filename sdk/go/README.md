# Orbit Go SDK

Add licence activation and feature checks to an installed Go application. The
client remembers activation, refreshes access in the background and restores
eligible saved access after a restart.

## Quick start

Use Go 1.27.1 or newer. To use the SDK from source, add it to your
application's `go.mod` with a replace path to your SDK checkout, then run
`go mod tidy`:

```go
require github.com/mayvqt/orbit-sdk/sdk/go v0.0.0

replace github.com/mayvqt/orbit-sdk/sdk/go => ../Orbit-SDK/sdk/go
```

Copy the public app key from **Integration** in your Orbit dashboard, starting
with the Test environment, and set it before launching your app:

```sh
export ORBIT_APP_KEY='orbit_app_test_…'
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

`EnsureAccess` calls the prompt only when the installation has no activation.
An outage or a licence without the feature never prompts for another key. Call
`RequireAccess` immediately before each later protected operation; it checks
online when a refresh is due. `Snapshot` and `HasFeature` are for display only.
Match failures with `errors.Is(err, orbit.ErrNotActivated)` or
`orbit.ErrFeatureUnavailable`.

The app key is public configuration, not a secret. Keep licence keys and
passwords out of source, command-line arguments and logs; the SDK never saves
them. See the [console example](../../examples/go/licensed-export/README.md) for
an end-to-end flow.

## Installation state

`Open` stores private state for the current user: owner-only files on Linux and
macOS, and current-user DPAPI on Windows. It sends a scoped `machine_v1`
fingerprint when the native identity is available, never the raw identifier.
On macOS, build with cgo enabled and the Xcode Command Line Tools installed;
with `CGO_ENABLED=0`, `Open` returns `ErrNativeSupportRequired`.

Pass `orbit.Options{StatePath: ...}` to choose a dedicated absolute directory,
for example for a service account or persistent container volume. Share one
`*Client` within a process; another process that opens the same state receives
`ErrInstallationInUse`. `Close` stops refresh and saves state without
deactivating the licence. [Advanced options](advanced.md#installed-options-and-machine-binding)
cover disabling binding for shared images and custom identities.

## Customer accounts

Customer accounts belong to people using your software, separately from your
Orbit dashboard account. After a customer registers and confirms the email
link, sign in and activate one of their licences:

```go
if _, err := client.Login(ctx, username, password); err != nil { return err }
page, err := client.OwnedLicences(ctx, "")
if err != nil { return err }
if _, err := client.ActivateAccount(ctx, page.Items[0].ID); err != nil { return err }
if _, err := client.RequireAccess(ctx, "export"); err != nil { return err }
```

Sign-in alone grants no licensed access. `EnsureAccess` covers only the
licence-key flow. [Customer accounts](advanced.md#customer-accounts) covers
registration, claiming keys, paging and logout.

## Long-term offline files

For a machine that stays disconnected longer than a connected grant allows,
configure a trusted offline-purpose JWKS. Ship it with your application or
fetch it from the app-key origin over verified HTTPS; never take keys from the
imported file or from the person providing it.

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
	// Transfer this public request to your authorized issuance workflow.
	file, err := os.ReadFile("licence.orbit")
	if err != nil { return err }
	if _, err := client.ImportOfflineFile(ctx, file); err != nil { return err }
	_, err = client.RequireAccess(ctx, "export")
	return err
}
```

This function uses the Quick start imports plus `encoding/json`. The request
contains the app key and installation identity, but no licence key, session or
credential. Import verifies and durably saves the file before returning access;
reimporting it never extends its expiry. While a file is active,
`RequireAccess` neither refreshes nor prompts, and an expired file returns
`offline_file_expired`.

An issued file cannot be revoked while the machine is disconnected. Sequence
and clock floors prevent ordinary replay and clock rollback, but restoring a
complete old machine or VM snapshot cannot be detected reliably. Tell customers
about this limit before issuing long-term access.

## Floating seats

Floating policies acquire a seat automatically after activation and renew it in
memory. `RequireAccess` checks the current signed interval locally, and the
snapshot's `Session` shows its ID, sequence and deadlines. A full seat pool, an
expired seat or an outage never asks for another licence key.

Call `EndSession(ctx)` when your app becomes idle and `StartSession(ctx)` when
it resumes. Ending clears local access before contacting Orbit and disables
automatic reacquisition. For an ordinary licence these calls do nothing, and
offline-file mode never switches online on its own.

`Close` makes a bounded attempt to release the seat and keeps the installation
credential. After a crash or failed release, the old seat stays occupied until
its interval ends, at most 120 seconds. During an outage the app keeps only the
current verified interval, so a remote revocation takes effect locally at that
deadline.

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

Compare the increasing release number built into your app, not display
versions. Discovery defaults to the `stable` channel and the running desktop
target; pass `orbit.UpdateOptions{Channel: "beta", Platform: "linux",
Architecture: "arm64"}` for an explicit target. There is no fallback to another
target.

The file streams directly from the seller over verified HTTPS, with no bearer
credential on any redirect. The SDK checks identity encoding, exact length and
SHA-256, then moves the file into place atomically. An existing destination is
refused unless you pass `orbit.DownloadOptions{ReplaceExisting: true}`; a failed
or cancelled download leaves it untouched. The SDK never runs or unpacks an
installer. Keep authorizations in memory and out of logs.

## Usage and resources

Configure an `exports` usage limit, then reserve a unit before doing the work:

```go
result, err := client.Consume(ctx, "exports", 1, exportJobID)
if err != nil { return err }
fmt.Println("Remaining exports:", result.Remaining)
// Perform the export and record its result with exportJobID.
```

`Usage(ctx, name)` and `Resources(ctx, name)` read the current authoritative
counters. `AcquireResource(ctx, name, resourceID, units)` returns an allocation;
remove the actual resource before calling `ReleaseResource(ctx, name,
allocationID)`. Closing, logging out and outages do not release allocations.

Operation IDs are optional and generated securely. Pass a stable job ID of
16–128 characters as the final argument when a retry must survive a restart.
A `*orbit.MutationError` carries `OperationID`, `Uncertain` and, for capacity
denials, validated `Usage` or `Resources` counters. Retry an uncertain outcome
with the same ID and identical input; a new ID is a new operation.

A usage retry returns its original debit or denial, even across a period
boundary. A resource retry returns the original allocation with its current
state and counter, so an old acquire can report `State == "released"` without
reactivating it. A later business failure does not refund usage.

These calls always go online with the current activation. They do not acquire
floating seats, offline files cannot authorize them, and `RequireAccess` never
consumes quota. Installed programs can be modified to skip reporting, so run
the metering check and the work on your trusted backend when enforcement must
be authoritative.

## Verify seller download tickets

If you serve protected artifacts, verify Orbit's short-lived bearer ticket on
your seller backend before looking up the artifact in your own registry.
Configure the exact HTTPS endpoint and a trusted connected-purpose JWKS; never
take keys or a destination URL from the ticket. The verifier makes no network
requests.

```go
package main

import (
	"fmt"
	"os"

	orbit "github.com/mayvqt/orbit-sdk/sdk/go"
)

func main() {
	keys, err := os.ReadFile("connected-jwks.json")
	if err != nil { panic(err) }
	verifier, err := orbit.NewDownloadTicketVerifier(os.Getenv("ORBIT_APP_KEY"), "https://downloads.example.com/artifacts", keys)
	if err != nil { panic(err) }
	ticket, err := verifier.Verify(os.Getenv("ORBIT_DOWNLOAD_TICKET"))
	if err != nil { panic(err) }
	// Match every returned field against the seller's artifact registry.
	fmt.Printf("artifact %s: %d bytes, sha256 %s\n", ticket.ArtifactID(), ticket.ByteLength(), ticket.SHA256())
}
```

An invalid or expired ticket returns an `orbit.ErrDenied` match with code
`invalid_download_ticket`. A ticket expires within 120 seconds and can be
replayed until then. Treat it as a secret, never log it, and never use an
artifact ID as an unchecked filesystem path. After matching it, serve the file
or issue a storage URL that expires no later than `ticket.ExpiresAt()`. The
[seller example](../../examples/python/seller-downloads/README.md) shows a
complete endpoint.
