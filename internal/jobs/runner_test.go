package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"arca/internal/database"
	"arca/migrations"
)

func TestRunnerCompletesRetriesAndDeadLettersDurably(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := database.Open(ctx, database.Config{Path: filepath.Join(t.TempDir(), "arca.sqlite3"), Migrations: migrations.Files})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	runner := New(db.Writer(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	runner.now = func() time.Time { return now }
	completed := 0
	runner.Register("complete", func(context.Context, json.RawMessage) error {
		completed++
		return nil
	})
	failure := errors.New("deterministic worker failure")
	runner.Register("fail", func(context.Context, json.RawMessage) error { return failure })

	completedID, err := runner.Enqueue(ctx, "complete", map[string]string{"value": "safe"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := db.Reader().QueryRowContext(ctx, `SELECT state FROM jobs WHERE id = ?`, completedID).Scan(&state); err != nil || state != "completed" || completed != 1 {
		t.Fatalf("completed state=%q calls=%d error=%v", state, completed, err)
	}

	failedID, err := runner.Enqueue(ctx, "fail", map[string]bool{"retry": true}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().ExecContext(ctx, `UPDATE jobs SET max_attempts = 1 WHERE id = ?`, failedID); err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(ctx); !errors.Is(err, failure) {
		t.Fatalf("failure result = %v", err)
	}
	var attempts int
	var lastError string
	if err := db.Reader().QueryRowContext(ctx, `SELECT state, attempts, last_error FROM jobs WHERE id = ?`, failedID).Scan(&state, &attempts, &lastError); err != nil {
		t.Fatal(err)
	}
	if state != "dead" || attempts != 1 || lastError != failure.Error() {
		t.Fatalf("dead job state=%q attempts=%d error=%q", state, attempts, lastError)
	}
	if err := runner.Retry(ctx, failedID); err != nil {
		t.Fatal(err)
	}
	if err := db.Reader().QueryRowContext(ctx, `SELECT state, COALESCE(last_error, '') FROM jobs WHERE id = ?`, failedID).Scan(&state, &lastError); err != nil || state != "queued" || lastError != "" {
		t.Fatalf("retried state=%q error=%q query=%v", state, lastError, err)
	}
}

func TestRunnerReclaimsExpiredLease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := database.Open(ctx, database.Config{Path: filepath.Join(t.TempDir(), "arca.sqlite3"), Migrations: migrations.Files})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	runner := New(db.Writer(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	runner.now = func() time.Time { return now }
	called := false
	runner.Register("lease", func(context.Context, json.RawMessage) error { called = true; return nil })
	id, err := runner.Enqueue(ctx, "lease", nil, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().ExecContext(ctx, `UPDATE jobs SET state='running', attempts=1, lease_until=? WHERE id=?`, stamp(now.Add(-time.Second)), id); err != nil {
		t.Fatal(err)
	}
	if err := runner.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("expired job lease was not reclaimed")
	}
	var state string
	var attempts int
	if err := db.Reader().QueryRowContext(ctx, `SELECT state, attempts FROM jobs WHERE id=?`, id).Scan(&state, &attempts); err != nil || state != "completed" || attempts != 2 {
		t.Fatalf("reclaimed state=%q attempts=%d error=%v", state, attempts, err)
	}
}
