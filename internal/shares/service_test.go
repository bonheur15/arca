package shares

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"arca/internal/database"
	"arca/migrations"
)

func TestPublicShareRedeemAndLiveDescendant(t *testing.T) {
	db := testDB(t)
	now := time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC)
	owner, root, child := seedOwnerAndTree(t, db, now)
	service, err := New(db, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	created, err := service.CreatePublic(context.Background(), CreatePublicInput{OwnerID: owner, RootIDs: []string{root}, TTL: 10 * time.Minute, RedemptionLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(created.Code) != 5 {
		t.Fatalf("code length = %d", len(created.Code))
	}
	session, err := service.Redeem(context.Background(), created.Code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Redeem(context.Background(), created.Code); !is(err, ErrPublicUnavailable) {
		t.Fatalf("second redemption error = %v", err)
	}
	resolved, err := service.ResolvePublicSession(context.Background(), session.Token)
	if err != nil || resolved.ShareID != created.ID {
		t.Fatalf("resolve = %#v, %v", resolved, err)
	}
	allowed, err := service.CanAccessPublicNode(context.Background(), created.ID, child)
	if err != nil || !allowed {
		t.Fatalf("live descendant allowed = %v, %v", allowed, err)
	}
}

func TestInternalPermissionInheritance(t *testing.T) {
	db := testDB(t)
	now := time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC)
	owner, root, child := seedOwnerAndTree(t, db, now)
	recipient := "0198a000-0000-7000-8000-000000000004"
	seedUser(t, db, recipient, "receiver", "receiver@example.com", now)
	service, err := New(db, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	share, err := service.CreateInternal(context.Background(), CreateInternalInput{
		OwnerID: owner, RootIDs: []string{root}, RecipientIDs: []string{recipient}, Permission: PermissionViewer,
	})
	if err != nil {
		t.Fatal(err)
	}
	permission, err := service.PermissionForNode(context.Background(), recipient, child)
	if err != nil || permission != PermissionViewer {
		t.Fatalf("permission = %q, %v", permission, err)
	}
	if err := service.RevokeInternal(context.Background(), owner, share.ID, false); err != nil {
		t.Fatal(err)
	}
	permission, err = service.PermissionForNode(context.Background(), recipient, child)
	if err != nil || permission != PermissionNone {
		t.Fatalf("revoked permission = %q, %v", permission, err)
	}
}

func TestInternalSharingRespectsOwnerPolicy(t *testing.T) {
	db := testDB(t)
	now := time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC)
	owner, root, _ := seedOwnerAndTree(t, db, now)
	recipient := "0198a000-0000-7000-8000-000000000014"
	seedUser(t, db, recipient, "blocked-receiver", "blocked@example.com", now)
	if _, err := db.Exec(`UPDATE user_policies SET allow_internal_sharing = 0 WHERE user_id = ?`, owner); err != nil {
		t.Fatal(err)
	}
	service, err := New(db, []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.CreateInternal(context.Background(), CreateInternalInput{
		OwnerID: owner, RootIDs: []string{root}, RecipientIDs: []string{recipient}, Permission: PermissionViewer,
	})
	if !is(err, ErrForbidden) {
		t.Fatalf("internal share policy error = %v", err)
	}
}

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	opened, err := database.Open(context.Background(), database.Config{Path: filepath.Join(t.TempDir(), "arca.sqlite3"), Migrations: migrations.Files})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	return opened.Writer()
}

func seedOwnerAndTree(t *testing.T, db *sql.DB, now time.Time) (string, string, string) {
	t.Helper()
	owner := "0198a000-0000-7000-8000-000000000001"
	root := "0198a000-0000-7000-8000-000000000002"
	child := "0198a000-0000-7000-8000-000000000003"
	seedUser(t, db, owner, "owner", "owner@example.com", now)
	stamp := now.Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO nodes(id, owner_id, parent_id, kind, name, name_key, created_by, created_at, updated_at) VALUES
        (?, ?, NULL, 'folder', '', '', ?, ?, ?),
        (?, ?, ?, 'folder', 'Shared', 'shared', ?, ?, ?)`, root, owner, owner, stamp, stamp, child, owner, root, owner, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE users SET root_node_id = ? WHERE id = ?`, root, owner); err != nil {
		t.Fatal(err)
	}
	return owner, root, child
}

func seedUser(t *testing.T, db *sql.DB, id, username, email string, now time.Time) {
	t.Helper()
	stamp := now.Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO users(id, username, username_key, email, email_key, role, state, quota_bytes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'member', 'active', 1000000, ?, ?)`, id, username, username, email, email, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO user_policies(user_id, updated_at) VALUES (?, ?)`, id, stamp); err != nil {
		t.Fatal(err)
	}
}

func is(err, target error) bool { return err == target }
