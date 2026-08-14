package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {
	t.Setenv("ARCA_WORKOS_API_KEY", "")
	t.Setenv("ARCA_COOKIE_KEY", "")
	t.Setenv("ARCA_CODE_HMAC_KEY", "")
	t.Setenv("ARCA_STATUS_HMAC_KEY", "")
	dir := t.TempDir()
	runtime, err := Load(Overrides{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureLayout(runtime.Layout); err != nil {
		t.Fatal(err)
	}
	runtime.File.InstanceName = "Archive"
	runtime.File.PublicURL = "http://localhost:8080"
	runtime.File.WorkOSClientID = "client_test"
	runtime.Secrets.WorkOSAPIKey = "sk_test"
	if err := runtime.EnsureSecrets(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(Overrides{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.File.InstanceName != "Archive" || loaded.Secrets.WorkOSAPIKey != "sk_test" {
		t.Fatalf("unexpected loaded configuration: %#v", loaded)
	}
	info, err := os.Stat(filepath.Join(dir, "secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected secret permissions: %o", info.Mode().Perm())
	}
}

func TestLockIsExclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "instance.lock")
	first, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := AcquireLock(path); err == nil {
		t.Fatal("second lock unexpectedly succeeded")
	}
}

func TestRemoteHTTPRejected(t *testing.T) {
	runtime := Runtime{
		File:    FileConfig{InstanceName: "Arca", PublicURL: "http://example.com", WorkOSClientID: "client"},
		Secrets: Secrets{WorkOSAPIKey: "secret"},
	}
	if err := runtime.ValidateConfigured(); err == nil {
		t.Fatal("expected insecure remote URL to be rejected")
	}
}

func TestEnsureLayoutRejectsIntermediateSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "storage")); err != nil {
		t.Fatal(err)
	}
	layout, err := ResolveLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureLayout(layout); err == nil {
		t.Fatal("intermediate storage symlink unexpectedly accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "blobs")); !os.IsNotExist(err) {
		t.Fatalf("layout escaped through symlink: %v", err)
	}
}

func TestEnsureLayoutSecuresIntermediateDirectories(t *testing.T) {
	root := t.TempDir()
	storage := filepath.Join(root, "storage")
	if err := os.Mkdir(storage, 0o755); err != nil {
		t.Fatal(err)
	}
	layout, err := ResolveLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureLayout(layout); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(storage)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("storage mode = %o, want 700", info.Mode().Perm())
	}
}
