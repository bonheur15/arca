package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"arca/api"
	"arca/internal/app"
	"arca/internal/backup"
	"arca/internal/config"
	"arca/internal/httpapi"
	webassets "arca/web"
)

var (
	version = "dev"
	commit  = "unknown"
	builtAt = "unknown"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "arca:", err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 {
		usage(stderr)
		return errors.New("a command is required")
	}
	switch arguments[0] {
	case "serve":
		return serve(arguments[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "Arca %s\ncommit: %s\nbuilt: %s\n", version, commit, builtAt)
		return nil
	case "doctor":
		return doctor(arguments[1:], stdout, stderr)
	case "backup":
		return createBackup(arguments[1:], stdout, stderr)
	case "restore":
		return restore(arguments[1:], stdout, stderr)
	case "admin":
		return admin(arguments[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return nil
	default:
		usage(stderr)
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func usage(output io.Writer) {
	fmt.Fprintln(output, `Arca — advanced self-hosted file storage

Usage:
  arca serve [--listen ADDRESS] [--data-dir PATH] [--tls-cert PATH --tls-key PATH]
  arca version
  arca doctor [--data-dir PATH]
  arca backup [--data-dir PATH] --output PATH
  arca restore --verify-only --source PATH
  arca restore --source PATH --data-dir EMPTY_PATH
  arca admin recovery-code [--data-dir PATH]
  arca admin add-superadmin [--data-dir PATH] --recovery-code CODE --username NAME --email ADDRESS

Environment variables override persisted configuration. See docs/operator-runbook.md.`)
}

func runtimeFlags(name string, arguments []string) (*flag.FlagSet, config.Overrides, error) {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var overrides config.Overrides
	set.StringVar(&overrides.Listen, "listen", "", "listen address")
	set.StringVar(&overrides.DataDir, "data-dir", "", "data directory")
	set.StringVar(&overrides.TLSCert, "tls-cert", "", "TLS certificate")
	set.StringVar(&overrides.TLSKey, "tls-key", "", "TLS private key")
	if err := set.Parse(arguments); err != nil {
		return nil, overrides, err
	}
	if set.NArg() != 0 {
		return nil, overrides, fmt.Errorf("unexpected arguments: %s", strings.Join(set.Args(), " "))
	}
	return set, overrides, nil
}

func logger(output io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func serve(arguments []string, stdout, stderr io.Writer) error {
	_, overrides, err := runtimeFlags("serve", arguments)
	if err != nil {
		return err
	}
	cfg, err := config.Load(overrides)
	if err != nil {
		return err
	}
	rootContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	log := logger(stderr)
	runtime, err := app.Open(rootContext, cfg, version, log)
	if err != nil {
		return err
	}
	defer runtime.Close()
	status, err := runtime.Bootstrap.Status(rootContext)
	if err != nil {
		return err
	}
	if status.Initialized {
		if err := runtime.Config.ValidateConfigured(); err != nil {
			return fmt.Errorf("configured instance is not safe to serve: %w", err)
		}
	} else {
		fmt.Fprintln(stderr, "\nArca requires first-run setup.")
		fmt.Fprintln(stderr, "One-time setup code (expires in 30 minutes):")
		fmt.Fprintln(stderr, runtime.SetupCode)
		fmt.Fprintln(stderr, "Open /setup through this instance. The code is never exposed over the API.")
		fmt.Fprintln(stderr)
	}
	if err := runtime.StartBackground(rootContext); err != nil {
		return err
	}
	handler, err := httpapi.NewServer(runtime, webassets.Dist, api.Files, log)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", runtime.Config.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", runtime.Config.Listen, err)
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		BaseContext:       func(net.Listener) context.Context { return rootContext },
	}
	serveError := make(chan error, 1)
	go func() {
		log.Info("Arca listening", "address", listener.Addr().String(), "version", version, "data_dir", runtime.Config.Layout.Root)
		if runtime.Config.TLSCert != "" {
			serveError <- server.ServeTLS(listener, runtime.Config.TLSCert, runtime.Config.TLSKey)
		} else {
			serveError <- server.Serve(listener)
		}
	}()
	select {
	case err := <-serveError:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-rootContext.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			_ = server.Close()
			return fmt.Errorf("graceful shutdown: %w", err)
		}
	}
	return nil
}

func doctor(arguments []string, stdout, stderr io.Writer) error {
	_, overrides, err := runtimeFlags("doctor", arguments)
	if err != nil {
		return err
	}
	cfg, err := config.Load(overrides)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runtime, err := app.Open(ctx, cfg, version, logger(stderr))
	if err != nil {
		return err
	}
	defer runtime.Close()
	if err := runtime.Database.Check(ctx); err != nil {
		return err
	}
	status, err := runtime.Bootstrap.Status(ctx)
	if err != nil {
		return err
	}
	free, err := runtime.Storage.FreeBytes()
	if err != nil {
		return err
	}
	result := map[string]any{
		"ok": true, "initialized": status.Initialized, "sqlite_version": runtime.SQLiteVersion,
		"data_dir": runtime.Config.Layout.Root, "filesystem_free_bytes": free,
		"filesystem_reserve_bytes":      runtime.Config.File.FilesystemReserveBytes,
		"workos_credentials_configured": runtime.Config.File.WorkOSClientID != "" && runtime.Config.Secrets.WorkOSAPIKey != "",
	}
	encoded, _ := json.MarshalIndent(result, "", "  ")
	fmt.Fprintln(stdout, string(encoded))
	return nil
}

func createBackup(arguments []string, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet("backup", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	dataDir := set.String("data-dir", "", "data directory")
	output := set.String("output", "", "backup destination")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *output == "" {
		return errors.New("--output is required")
	}
	cfg, err := config.Load(config.Overrides{DataDir: *dataDir})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtime, err := app.Open(ctx, cfg, version, logger(stderr))
	if err != nil {
		return fmt.Errorf("open instance for backup (stop a running server first): %w", err)
	}
	defer runtime.Close()
	manifest, err := runtime.Backup.Create(ctx, *output)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Backup complete: %s\n%d blobs, %d bytes, schema %d\n", *output, len(manifest.Blobs), manifest.TotalBytes, manifest.SchemaVersion)
	return nil
}

func restore(arguments []string, stdout, _ io.Writer) error {
	set := flag.NewFlagSet("restore", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	source := set.String("source", "", "backup source")
	dataDir := set.String("data-dir", "", "empty destination data directory")
	verifyOnly := set.Bool("verify-only", false, "verify without restoring")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if *source == "" {
		return errors.New("--source is required")
	}
	ctx := context.Background()
	if *verifyOnly {
		manifest, err := backup.Verify(ctx, *source)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Backup verified: instance %s, schema %d, %d blobs\n", manifest.InstanceID, manifest.SchemaVersion, len(manifest.Blobs))
		return nil
	}
	if *dataDir == "" {
		return errors.New("--data-dir is required for restore")
	}
	layout, err := config.ResolveLayout(*dataDir)
	if err != nil {
		return err
	}
	empty, err := directoryEmpty(layout.Root)
	if err != nil {
		return err
	}
	if !empty {
		return fmt.Errorf("restore destination is not empty: %s", layout.Root)
	}
	manifest, err := backup.Restore(ctx, *source, backup.Layout{Database: layout.Database, BlobDir: layout.BlobDir})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Restore complete: instance %s, %d blobs\nRe-enter WorkOS credentials with ARCA_WORKOS_CLIENT_ID and ARCA_WORKOS_API_KEY before starting Arca.\n", manifest.InstanceID, len(manifest.Blobs))
	return nil
}

func directoryEmpty(path string) (bool, error) {
	directory, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	defer directory.Close()
	_, err = directory.Readdirnames(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	return false, err
}

func admin(arguments []string, stdout, stderr io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("admin requires recovery-code or add-superadmin")
	}
	switch arguments[0] {
	case "recovery-code":
		set := flag.NewFlagSet("admin recovery-code", flag.ContinueOnError)
		set.SetOutput(io.Discard)
		dataDir := set.String("data-dir", "", "data directory")
		if err := set.Parse(arguments[1:]); err != nil {
			return err
		}
		runtime, closeRuntime, err := openCommandRuntime(*dataDir, stderr)
		if err != nil {
			return err
		}
		defer closeRuntime()
		code, expires, err := runtime.CreateRecoveryCode(context.Background())
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "One-use recovery code (expires %s):\n%s\n", expires.Format(time.RFC3339), code)
		return nil
	case "add-superadmin":
		set := flag.NewFlagSet("admin add-superadmin", flag.ContinueOnError)
		set.SetOutput(io.Discard)
		dataDir := set.String("data-dir", "", "data directory")
		code := set.String("recovery-code", "", "one-use recovery code")
		username := set.String("username", "", "username")
		email := set.String("email", "", "email")
		displayName := set.String("display-name", "", "display name")
		quota := set.Int64("quota-bytes", 50<<30, "quota in bytes")
		if err := set.Parse(arguments[1:]); err != nil {
			return err
		}
		if *code == "" || *username == "" || *email == "" {
			return errors.New("--recovery-code, --username, and --email are required")
		}
		runtime, closeRuntime, err := openCommandRuntime(*dataDir, stderr)
		if err != nil {
			return err
		}
		defer closeRuntime()
		user, err := runtime.AddRecoverySuperadmin(context.Background(), *code, *username, *email, *displayName, *quota)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Superadmin ready: %s <%s> (%s)\n", user.Username, user.Email, user.ID)
		return nil
	default:
		return fmt.Errorf("unknown admin command %q", arguments[0])
	}
}

func openCommandRuntime(dataDir string, stderr io.Writer) (*app.Runtime, func(), error) {
	cfg, err := config.Load(config.Overrides{DataDir: dataDir})
	if err != nil {
		return nil, func() {}, err
	}
	runtime, err := app.Open(context.Background(), cfg, version, logger(stderr))
	if err != nil {
		return nil, func() {}, fmt.Errorf("open instance (stop a running server first): %w", err)
	}
	return runtime, func() { _ = runtime.Close() }, nil
}
