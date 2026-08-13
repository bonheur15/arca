package files

import (
	"context"
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
