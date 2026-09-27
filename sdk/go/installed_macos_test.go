//go:build darwin && cgo

package orbit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMacOSInstalledRejectsReplacedLeaseWithoutStateWrites(t *testing.T) {
	fixture := newInstalledFixture(t, true)
	path := filepath.Join(installedTestTempDir(t), "state")
	client := mustInstalledOpen(t, fixture, path)
	mustInstalledActivate(t, client)

	dataPath := filepath.Join(path, installedDataName)
	leasePath := filepath.Join(path, storageLockName)
	dataBefore, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	replacedPath := leasePath + ".saved"
	if err := os.Rename(leasePath, replacedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leasePath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	leaseBefore, err := os.ReadFile(leasePath)
	if err != nil {
		t.Fatal(err)
	}
	validationCount := fixture.validation.Load()
	activationCount := fixture.activation.Load()

	if _, err := client.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrStorage) {
		t.Fatalf("warm access trusted a replaced lease: %v", err)
	}
	if fixture.validation.Load() != validationCount || fixture.activation.Load() != activationCount {
		t.Fatal("storage verification failure sent a network request")
	}
	if current, err := os.ReadFile(dataPath); err != nil || !bytes.Equal(current, dataBefore) {
		t.Fatal("storage verification failure changed installed state")
	}
	if current, err := os.ReadFile(leasePath); err != nil || !bytes.Equal(current, leaseBefore) {
		t.Fatal("storage verification failure wrote through the replaced lease")
	}
	if err := client.Close(); !errors.Is(err, ErrStorage) {
		t.Fatalf("close hid the poisoned storage failure: %v", err)
	}
	if current, err := os.ReadFile(dataPath); err != nil || !bytes.Equal(current, dataBefore) {
		t.Fatal("close changed installed state after lease replacement")
	}
	if current, err := os.ReadFile(leasePath); err != nil || !bytes.Equal(current, leaseBefore) {
		t.Fatal("close wrote through the replaced lease")
	}
}

func TestMacOSInstalledRejectsRenamedParentWithoutStateWrites(t *testing.T) {
	fixture := newInstalledFixture(t, true)
	parent := filepath.Join(installedTestTempDir(t), "state-parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "state")
	client := mustInstalledOpen(t, fixture, path)
	mustInstalledActivate(t, client)
	dataPath := filepath.Join(path, installedDataName)
	leasePath := filepath.Join(path, storageLockName)
	dataBefore, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	leaseBefore, err := os.ReadFile(leasePath)
	if err != nil {
		t.Fatal(err)
	}

	renamedParent := parent + ".saved"
	if err := os.Rename(parent, renamedParent); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	validationCount := fixture.validation.Load()
	activationCount := fixture.activation.Load()
	if _, err := client.RequireAccess(context.Background(), "export"); !errors.Is(err, ErrStorage) {
		t.Fatalf("warm access trusted a replaced parent: %v", err)
	}
	if fixture.validation.Load() != validationCount || fixture.activation.Load() != activationCount {
		t.Fatal("storage verification failure sent a network request")
	}
	if current, err := os.ReadFile(filepath.Join(renamedParent, "state", installedDataName)); err != nil || !bytes.Equal(current, dataBefore) {
		t.Fatal("storage verification failure changed installed state")
	}
	if current, err := os.ReadFile(filepath.Join(renamedParent, "state", storageLockName)); err != nil || !bytes.Equal(current, leaseBefore) {
		t.Fatal("storage verification failure wrote through the renamed parent")
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatal("storage verification failure wrote into the replacement parent")
	}
	if err := client.Close(); !errors.Is(err, ErrStorage) {
		t.Fatalf("close hid the poisoned storage failure: %v", err)
	}
	if current, err := os.ReadFile(filepath.Join(renamedParent, "state", installedDataName)); err != nil || !bytes.Equal(current, dataBefore) {
		t.Fatal("close changed installed state after parent replacement")
	}
}
