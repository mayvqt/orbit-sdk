package orbit

import (
	"context"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
)

type benchmarkInstalledFiles struct {
	inner  installedFiles
	checks atomic.Int64
	writes atomic.Int64
}

func (files *benchmarkInstalledFiles) read() ([]byte, error) { return files.inner.read() }
func (files *benchmarkInstalledFiles) write(data []byte) error {
	files.writes.Add(1)
	return files.inner.write(data)
}
func (files *benchmarkInstalledFiles) check() error {
	files.checks.Add(1)
	return files.inner.check()
}
func (files *benchmarkInstalledFiles) close() error { return files.inner.close() }

func BenchmarkInstalledWarmAccess(b *testing.B) {
	for _, operation := range []string{"RequireAccess", "Snapshot"} {
		b.Run(operation, func(b *testing.B) {
			fixture := newInstalledFixture(b, false)
			transport, err := NewTransport("https://orbit.example.test")
			if err != nil {
				b.Fatal(err)
			}
			var requests atomic.Int64
			transport.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				requests.Add(1)
				return fixture.respond(request)
			})
			client, err := openInstalled(context.Background(), testAppKey(), installedOptions(filepath.Join(installedTestTempDir(b), "state")), transport)
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				if err := client.Close(); err != nil {
					b.Errorf("close installed fixture: %v", err)
				}
				transport.CloseIdleConnections()
			})
			if snapshot, err := client.Activate(context.Background(), "synthetic-key"); err != nil || snapshot.Access != AccessOnline {
				b.Fatalf("activate signed fixture: snapshot=%+v err=%v", snapshot, err)
			}
			beforeRequests := requests.Load()
			if beforeRequests == 0 {
				b.Fatal("activation did not exercise the signed HTTP fixture")
			}

			client.installed.mu.Lock()
			counted := &benchmarkInstalledFiles{inner: client.installed.files}
			client.installed.files = counted
			client.installed.mu.Unlock()

			check := func() error {
				if operation == "RequireAccess" {
					_, err := client.RequireAccess(context.Background(), "export")
					return err
				}
				_, err := client.Snapshot()
				return err
			}
			if err := check(); err != nil {
				b.Fatalf("warmup: %v", err)
			}
			beforeChecks, beforeWrites := counted.checks.Load(), counted.writes.Load()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := check(); err != nil {
					b.Fatalf("warm %s: %v", operation, err)
				}
			}
			b.StopTimer()
			if after := requests.Load(); after != beforeRequests {
				b.Fatalf("warm %s sent HTTP requests: before=%d after=%d", operation, beforeRequests, after)
			}
			if after := counted.writes.Load(); after != beforeWrites {
				b.Fatalf("warm %s wrote installed state: before=%d after=%d", operation, beforeWrites, after)
			}
			if checks := counted.checks.Load() - beforeChecks; checks < int64(b.N) {
				b.Fatalf("warm %s skipped storage checks: got %d for %d calls", operation, checks, b.N)
			}
		})
	}
}
