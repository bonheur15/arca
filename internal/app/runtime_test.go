package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"arca/internal/config"
)

func TestRuntimeInitializesLayoutAndRotatesSetupCode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dataDir := t.TempDir()
	cfg, err := config.Load(config.Overrides{DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	first, err := Open(ctx, cfg, "test", log)
	if err != nil {
		t.Fatal(err)
	}
	firstCode := first.SetupCode
	if len(firstCode) != 20 {
		t.Fatalf("setup code length = %d, want 20", len(firstCode))
	}
	status, err := first.Bootstrap.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status.Initialized || !status.SetupRequired {
		t.Fatalf("unexpected bootstrap status: %+v", status)
	}
	if err := first.Bootstrap.ValidateCode(ctx, firstCode); err != nil {
		t.Fatalf("validate setup code: %v", err)
	}
	if err := first.Bootstrap.ValidateCode(ctx, strings.Repeat("A", 20)); err == nil {
		t.Fatal("invalid setup code unexpectedly accepted")
	}

	secondCfg, err := config.Load(config.Overrides{DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, secondCfg, "test", log); err == nil || !strings.Contains(err.Error(), "another Arca process") {
		t.Fatalf("second runtime should fail the process lock, got %v", err)
	}
	for _, path := range []string{first.Config.Layout.Root, first.Config.Layout.DatabaseDir, first.Config.Layout.BlobDir, first.Config.Layout.StagingDir, first.Config.Layout.PreviewDir, first.Config.Layout.LockDir} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("directory %s mode = %o, want 700", path, info.Mode().Perm())
		}
	}
	for _, path := range []string{first.Config.Layout.ConfigFile, first.Config.Layout.SecretsFile} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("file %s mode = %o, want 600", path, info.Mode().Perm())
		}
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	reopenedCfg, err := config.Load(config.Overrides{DataDir: dataDir})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, reopenedCfg, "test", log)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.SetupCode == firstCode || len(reopened.SetupCode) != 20 {
		t.Fatalf("setup code was not replaced after restart: %q", reopened.SetupCode)
	}
	if err := reopened.Bootstrap.ValidateCode(ctx, firstCode); err == nil {
		t.Fatal("setup code from the previous process remained valid")
	}
}
