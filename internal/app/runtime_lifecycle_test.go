package app

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"arca/internal/accounts"
	"arca/internal/audit"
	"arca/internal/config"
	"arca/internal/database"
	"arca/internal/files"
	"arca/internal/jobs"
	"arca/internal/uploads"
	"arca/migrations"
)

func TestStartBackgroundReconcilesQuotaBeforeReturn(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, database.Config{Path: filepath.Join(t.TempDir(), "arca.sqlite3"), Migrations: migrations.Files})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repository := accounts.NewRepository(db.Writer())
	user, err := repository.CreateUser(ctx, accounts.CreateUserParams{
		Username: "quota-startup", Email: "quota-startup@example.com", Role: accounts.RoleMember,
		State: accounts.StateActive, QuotaBytes: 1_000, Policy: accounts.DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Writer().Exec(`INSERT INTO blobs(id, owner_id, storage_key, size_bytes, sha256, state, ref_count, created_at)
		VALUES ('startup-blob', ?, 'startup-opaque-key', 275, ?, 'ready', 1, ?)`, user.ID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec(`UPDATE users SET used_bytes = 0 WHERE id = ?`, user.ID); err != nil {
		t.Fatal(err)
	}
	storage, err := uploads.NewLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	uploadService := uploads.NewService(db, storage, uploads.ServiceOptions{})
	fileService := files.NewService(db, files.ServiceOptions{})
	runner := jobs.New(db.Writer(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	deletions := accounts.NewDeletionProcessor(repository, nil, storage, audit.NopRecorder{})
	registerJobs(runner, db, uploadService, fileService, deletions)
	runtime := &Runtime{
		Database: db, AccountRepo: repository, Files: fileService, Uploads: uploadService,
		Jobs: runner, Config: &config.Runtime{}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	background, cancel := context.WithCancel(ctx)
	if err := runtime.StartBackground(background); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	runtime.backgroundGroup.Wait()
	var used int64
	if err := db.Reader().QueryRow(`SELECT used_bytes FROM users WHERE id = ?`, user.ID).Scan(&used); err != nil || used != 275 {
		t.Fatalf("startup used bytes=%d err=%v", used, err)
	}
}
