package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"arca/internal/database"
	"arca/internal/uploads"
	"arca/migrations"
)

func TestCreateVerifyRestoreRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "database", "arca.sqlite3")
	db, err := database.Open(ctx, database.Config{Path: dbPath, Migrations: migrations.Files})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	storage, err := uploads.NewLocalStorage(root)
	if err != nil {
		t.Fatal(err)
	}
	const (
		userID     = "018f0000-0000-7000-8000-000000000001"
		rootID     = "018f0000-0000-7000-8000-000000000002"
		nodeID     = "018f0000-0000-7000-8000-000000000003"
		versionID  = "018f0000-0000-7000-8000-000000000004"
		blobID     = "018f0000-0000-7000-8000-000000000005"
		storageKey = "abcd018f000000007000800000000005"
	)
	payload := []byte("Arca backup round trip\n")
	digest := sha256.Sum256(payload)
	digestText := hex.EncodeToString(digest[:])
	staging, err := storage.OpenStaging("backup-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staging.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := staging.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := staging.Close(); err != nil {
		t.Fatal(err)
	}
	if err := storage.Finalize("backup-fixture", storageKey); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO instance_settings(singleton, instance_id, initialized, name, public_url, filesystem_reserve_bytes, created_at, updated_at)
			VALUES(1, ?, 1, 'Test Arca', 'https://arca.test', 0, ?, ?)`, []any{"018f0000-0000-7000-8000-000000000000", now, now}},
		{`INSERT INTO users(id, username, username_key, email, email_key, role, state, quota_bytes, used_bytes, root_node_id, created_at, updated_at)
			VALUES(?, 'owner', 'owner', 'owner@example.test', 'owner@example.test', 'superadmin', 'active', 1000000, ?, ?, ?, ?)`, []any{userID, len(payload), rootID, now, now}},
		{`INSERT INTO nodes(id, owner_id, parent_id, kind, name, name_key, created_by, created_at, updated_at)
			VALUES(?, ?, NULL, 'folder', '', '', ?, ?, ?)`, []any{rootID, userID, userID, now, now}},
		{`INSERT INTO blobs(id, owner_id, storage_key, size_bytes, sha256, state, ref_count, created_at)
			VALUES(?, ?, ?, ?, ?, 'ready', 1, ?)`, []any{blobID, userID, storageKey, len(payload), digestText, now}},
		{`INSERT INTO nodes(id, owner_id, parent_id, kind, name, name_key, mime_type, size_bytes, current_version_id, created_by, created_at, updated_at)
			VALUES(?, ?, ?, 'file', 'backup.txt', 'backup.txt', 'text/plain', ?, ?, ?, ?, ?)`, []any{nodeID, userID, rootID, len(payload), versionID, userID, now, now}},
		{`INSERT INTO file_versions(id, node_id, blob_id, sequence, size_bytes, sha256, mime_type, created_by, created_at)
			VALUES(?, ?, ?, 1, ?, ?, 'text/plain', ?, ?)`, []any{versionID, nodeID, blobID, len(payload), digestText, userID, now}},
		{`INSERT INTO idempotency_keys(actor_key, idempotency_key, request_hash, response_status, response_body, expires_at, created_at)
			VALUES('fixture', 'fixture-key', x'01', 200, x'7b7d', ?, ?)`, []any{time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), now}},
	}
	for _, statement := range statements {
		if _, err := db.Writer().ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("fixture statement failed: %v\n%s", err, statement.query)
		}
	}

	backupPath := filepath.Join(t.TempDir(), "snapshot")
	service := New(db.Writer(), Layout{Database: dbPath, BlobDir: filepath.Join(root, "storage", "blobs")}, "test-version")
	manifest, err := service.Create(ctx, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.InstanceID == "" || manifest.SchemaVersion != 1 || len(manifest.Blobs) != 1 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	if _, err := Verify(ctx, backupPath); err != nil {
		t.Fatalf("verify backup: %v", err)
	}

	restoreRoot := t.TempDir()
	restoredDB := filepath.Join(restoreRoot, "database", "arca.sqlite3")
	restoredBlobs := filepath.Join(restoreRoot, "storage", "blobs")
	if _, err := Restore(ctx, backupPath, Layout{Database: restoredDB, BlobDir: restoredBlobs}); err != nil {
		t.Fatalf("restore backup: %v", err)
	}
	restored, err := database.Open(ctx, database.Config{Path: restoredDB, Migrations: migrations.Files})
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var idempotencyCount int
	if err := restored.Reader().QueryRowContext(ctx, "SELECT COUNT(*) FROM idempotency_keys").Scan(&idempotencyCount); err != nil {
		t.Fatal(err)
	}
	if idempotencyCount != 0 {
		t.Fatalf("restored transient sessions were not invalidated: %d idempotency rows", idempotencyCount)
	}
	restoredBlob := filepath.Join(restoredBlobs, storageKey[:2], storageKey[2:4], storageKey)
	actual, err := os.ReadFile(restoredBlob)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != string(payload) {
		t.Fatalf("restored blob mismatch: %q", actual)
	}

	if err := os.WriteFile(filepath.Join(backupPath, manifest.Blobs[0].Path), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(ctx, backupPath); err == nil {
		t.Fatal("corrupted backup unexpectedly verified")
	}
}
