package files

import (
	"context"
	"fmt"
	"testing"
	"time"

	"arca/internal/database"
	"arca/migrations"
)

var testNow = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

func testDatabase(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(context.Background(), database.Config{
		Path:         t.TempDir() + "/database/arca.sqlite3",
		Migrations:   migrations.Files,
		MaxReadConns: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	_, err = db.Writer().Exec(`INSERT INTO instance_settings
        (singleton, instance_id, initialized, name, public_url, filesystem_reserve_bytes, created_at, updated_at)
        VALUES (1, 'instance-test', 1, 'Test Arca', 'https://arca.test', 0, ?, ?)`, timeText(testNow), timeText(testNow))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func addTestUser(t *testing.T, db *database.DB, id, username, role string, quota int64) {
	t.Helper()
	_, err := db.Writer().Exec(`INSERT INTO users
        (id, username, username_key, email, email_key, role, state, quota_bytes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`, id, username, username, username+"@example.test",
		username+"@example.test", role, quota, timeText(testNow), timeText(testNow))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Writer().Exec(`INSERT INTO user_policies(user_id, updated_at) VALUES (?, ?)`, id, timeText(testNow))
	if err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeName(t *testing.T) {
	t.Parallel()
	display, key, err := NormalizeName("Cafe\u0301.TXT")
	if err != nil {
		t.Fatal(err)
	}
	if display != "Café.TXT" || key != "café.txt" {
		t.Fatalf("normalized = %q / %q", display, key)
	}
	for _, invalid := range []string{"", "   ", ".", "..", "bad/name", "bad\x00name", "line\nfeed"} {
		if _, _, err := NormalizeName(invalid); ErrorCodeOf(err) != CodeInvalidName {
			t.Errorf("NormalizeName(%q) error = %v", invalid, err)
		}
	}
}

func TestFileTreeLifecycle(t *testing.T) {
	db := testDatabase(t)
	addTestUser(t, db, "user-one", "owner", "member", 1<<30)
	service := NewService(db, ServiceOptions{Now: func() time.Time { return testNow }})
	root, err := service.CreateUserRoot(context.Background(), "user-one")
	if err != nil {
		t.Fatal(err)
	}
	docs, err := service.CreateFolder(context.Background(), "user-one", root.ID, "Cafe\u0301")
	if err != nil {
		t.Fatal(err)
	}
	if docs.Name != "Café" {
		t.Fatalf("folder name = %q", docs.Name)
	}
	if _, err := service.CreateFolder(context.Background(), "user-one", root.ID, "CAFÉ"); ErrorCodeOf(err) != CodeConflict {
		t.Fatalf("duplicate normalized sibling error = %v", err)
	}
	child, err := service.CreateFolder(context.Background(), "user-one", docs.ID, "Child")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Move(context.Background(), "user-one", docs.ID, child.ID, docs.Revision); ErrorCodeOf(err) != CodeCycle {
		t.Fatalf("folder cycle error = %v", err)
	}
	renamed, err := service.Rename(context.Background(), "user-one", docs.ID, "Documents", docs.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Rename(context.Background(), "user-one", docs.ID, "Stale", docs.Revision); ErrorCodeOf(err) != CodeRevisionMismatch {
		t.Fatalf("stale rename error = %v", err)
	}
	if err := service.SetFavorite(context.Background(), "user-one", docs.ID, true); err != nil {
		t.Fatal(err)
	}
	favorites, err := service.ListFavorites(context.Background(), "user-one", ListOptions{})
	if err != nil || len(favorites.Items) != 1 || favorites.Items[0].ID != docs.ID {
		t.Fatalf("favorites = %+v, error = %v", favorites, err)
	}
	search, err := service.Search(context.Background(), "user-one", SearchOptions{Query: "doc"})
	if err != nil || len(search.Items) != 1 || search.Items[0].ID != docs.ID {
		t.Fatalf("search = %+v, error = %v", search, err)
	}
	copied, err := service.Copy(context.Background(), CopyRequest{
		ActorID: "user-one", NodeID: docs.ID, DestinationID: root.ID, KeepBoth: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if copied.Name != "Documents (1)" {
		t.Fatalf("copy name = %q", copied.Name)
	}
	copiedChildren, err := service.List(context.Background(), "user-one", copied.ID, ListOptions{})
	if err != nil || len(copiedChildren.Items) != 1 || copiedChildren.Items[0].Name != "Child" {
		t.Fatalf("copied children = %+v, error = %v", copiedChildren, err)
	}
	trashed, err := service.Trash(context.Background(), "user-one", docs.ID, renamed.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(context.Background(), "user-one", child.ID); ErrorCodeOf(err) != CodeNotFound {
		t.Fatalf("trashed descendant get error = %v", err)
	}
	trash, err := service.ListTrash(context.Background(), "user-one", ListOptions{})
	if err != nil || len(trash.Items) != 1 || trash.Items[0].ID != docs.ID {
		t.Fatalf("trash = %+v, error = %v", trash, err)
	}
	restored, err := service.Restore(context.Background(), "user-one", docs.ID, trashed.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if restored.TrashedAt != nil || restored.ParentID == nil || *restored.ParentID != root.ID {
		t.Fatalf("restored node = %+v", restored)
	}

	created := timeText(testNow)
	if _, err := db.Writer().Exec(`INSERT INTO blobs
		(id, owner_id, storage_key, size_bytes, sha256, state, ref_count, created_at)
		VALUES ('blob-id', 'user-one', 'blob-key', 5, 'hash', 'ready', 1, ?)`, created); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec(`INSERT INTO nodes
		(id, owner_id, parent_id, kind, name, name_key, mime_type, size_bytes, current_version_id,
		 revision, created_by, created_at, updated_at)
		VALUES ('file-id', 'user-one', ?, 'file', 'data.txt', 'data.txt', 'text/plain', 5, 'version-id',
		 1, 'user-one', ?, ?)`, docs.ID, created, created); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec(`INSERT INTO file_versions
		(id, node_id, blob_id, sequence, size_bytes, sha256, mime_type, created_by, created_at)
		VALUES ('version-id', 'file-id', 'blob-id', 1, 5, 'hash', 'text/plain', 'user-one', ?)`, created); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec("UPDATE users SET used_bytes = 5 WHERE id = 'user-one'"); err != nil {
		t.Fatal(err)
	}
	trashedAgain, err := service.Trash(context.Background(), "user-one", docs.ID, restored.Revision)
	if err != nil {
		t.Fatal(err)
	}
	purged, err := service.Purge(context.Background(), "user-one", docs.ID, trashedAgain.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if purged.NodesDeleted != 3 || purged.BlobsQueued != 1 {
		t.Fatalf("purge result = %+v", purged)
	}
	quota, err := service.Quota(context.Background(), "user-one")
	if err != nil || quota.StoredUsedBytes != 0 || quota.ActualUsedBytes != 0 || quota.Drift {
		t.Fatalf("quota after purge = %+v, error = %v", quota, err)
	}
}

func TestEditorAuthorizationUsesLiveFolderAncestry(t *testing.T) {
	db := testDatabase(t)
	addTestUser(t, db, "owner-id", "owner", "member", 1<<30)
	addTestUser(t, db, "editor-id", "editor", "member", 1<<30)
	service := NewService(db, ServiceOptions{Now: func() time.Time { return testNow }})
	ownerRoot, err := service.CreateUserRoot(context.Background(), "owner-id")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateUserRoot(context.Background(), "editor-id"); err != nil {
		t.Fatal(err)
	}
	shared, err := service.CreateFolder(context.Background(), "owner-id", ownerRoot.ID, "Shared")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Writer().Exec(`INSERT INTO shares
        (id, owner_id, permission, allow_editor_uploads, editor_allowance_bytes, created_at, updated_at)
		VALUES ('share-id', 'owner-id', 'editor', 1, 1024, ?, ?)`, timeText(testNow), timeText(testNow))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec("INSERT INTO share_roots(share_id, node_id) VALUES ('share-id', ?)", shared.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec("INSERT INTO share_recipients(share_id, user_id) VALUES ('share-id', 'editor-id')"); err != nil {
		t.Fatal(err)
	}
	child, err := service.CreateFolder(context.Background(), "editor-id", shared.ID, "From editor")
	if err != nil {
		t.Fatal(err)
	}
	if child.OwnerID != "owner-id" {
		t.Fatalf("child owner = %q", child.OwnerID)
	}
	if _, err := service.Rename(context.Background(), "editor-id", shared.ID, "Forbidden", shared.Revision); ErrorCodeOf(err) != CodeForbidden {
		t.Fatalf("editor mutated share root: %v", err)
	}
	if _, err := db.Writer().Exec("UPDATE shares SET revoked_at = ? WHERE id = 'share-id'", timeText(testNow)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(context.Background(), "editor-id", child.ID); ErrorCodeOf(err) != CodeForbidden {
		t.Fatalf("revoked editor still had access: %v", err)
	}
}

func TestVersionRetentionAndQuotaReconciliation(t *testing.T) {
	db := testDatabase(t)
	addTestUser(t, db, "retention-user", "retention", "member", 100)
	service := NewService(db, ServiceOptions{Now: func() time.Time { return testNow }})
	root, err := service.CreateUserRoot(context.Background(), "retention-user")
	if err != nil {
		t.Fatal(err)
	}
	created := timeText(testNow.Add(-40 * 24 * time.Hour))
	if _, err := db.Writer().Exec(`INSERT INTO nodes
		(id, owner_id, parent_id, kind, name, name_key, mime_type, size_bytes, current_version_id,
		 revision, created_by, created_at, updated_at)
		VALUES ('history-file', 'retention-user', ?, 'file', 'history.txt', 'history.txt', 'text/plain', 1,
		 'version-12', 1, 'retention-user', ?, ?)`, root.ID, created, created); err != nil {
		t.Fatal(err)
	}
	for sequence := 1; sequence <= 12; sequence++ {
		blobID := fmt.Sprintf("blob-%02d", sequence)
		versionID := fmt.Sprintf("version-%02d", sequence)
		if _, err := db.Writer().Exec(`INSERT INTO blobs
			(id, owner_id, storage_key, size_bytes, sha256, state, ref_count, created_at)
			VALUES (?, 'retention-user', ?, 1, ?, 'ready', 1, ?)`, blobID, "key-"+blobID, "hash-"+blobID, created); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Writer().Exec(`INSERT INTO file_versions
			(id, node_id, blob_id, sequence, size_bytes, sha256, mime_type, created_by, created_at)
			VALUES (?, 'history-file', ?, ?, 1, ?, 'text/plain', 'retention-user', ?)`,
			versionID, blobID, sequence, "hash-"+blobID, created); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Writer().Exec("UPDATE users SET used_bytes = 12 WHERE id = 'retention-user'"); err != nil {
		t.Fatal(err)
	}
	result, err := service.PruneVersions(context.Background(), "retention-user", 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.VersionsDeleted != 2 || result.BlobsQueued != 2 || result.BytesReleased != 2 {
		t.Fatalf("retention result = %+v", result)
	}
	versions, err := service.ListVersions(context.Background(), "retention-user", "history-file")
	if err != nil || len(versions) != 10 || versions[len(versions)-1].Sequence != 3 {
		t.Fatalf("retained versions = %+v, error = %v", versions, err)
	}
	if _, err := db.Writer().Exec("UPDATE users SET used_bytes = 99, reserved_bytes = 5 WHERE id = 'retention-user'"); err != nil {
		t.Fatal(err)
	}
	status, err := service.Quota(context.Background(), "retention-user")
	if err != nil || !status.Drift || status.ActualUsedBytes != 10 || status.ActualReservedBytes != 0 {
		t.Fatalf("drift status = %+v, error = %v", status, err)
	}
	status, err = service.ReconcileQuota(context.Background(), "retention-user")
	if err != nil || status.Drift || status.StoredUsedBytes != 10 || status.StoredReservedBytes != 0 {
		t.Fatalf("reconciled status = %+v, error = %v", status, err)
	}
	if _, err := db.Writer().Exec("UPDATE users SET quota_bytes = 5 WHERE id = 'retention-user'"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReconcileQuota(context.Background(), "retention-user"); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := db.Reader().QueryRow("SELECT state FROM users WHERE id = 'retention-user'").Scan(&state); err != nil || state != "over_quota" {
		t.Fatalf("quota state = %q, error = %v", state, err)
	}
}
