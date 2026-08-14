package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"arca/internal/audit"
	"arca/internal/database"
	"arca/migrations"
)

func TestDeletionTransferCompletesLocalBeforeIdentityAndAudits(t *testing.T) {
	db := openDeletionTestDB(t)
	repository := NewRepository(db.Writer())
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	repository.now = func() time.Time { return now }
	admin := createDeletionUser(t, repository, "admin-transfer", RoleSuperadmin, StateActive)
	source := createDeletionUser(t, repository, "source-transfer", RoleMember, StateActive)
	target := createDeletionUser(t, repository, "target-transfer", RoleMember, StateActive)
	completeWorkOS(t, repository, source.ID, "workos_source")
	seedDeletionFile(t, db.Writer(), source, 80)

	service := NewService(repository, nil, nil, audit.NewSQLRecorder(db.Writer()))
	service.now = func() time.Time { return now }
	user, err := service.ScheduleDeletion(context.Background(), source.ID, DeletionPlan{Mode: DeletionTransfer, TransferToUserID: target.ID}, MutationContext{ActorID: admin.ID})
	if err != nil {
		t.Fatal(err)
	}
	if user.State != StateDeletionPending || user.DeletionDueAt == nil || !user.DeletionDueAt.Equal(now.Add(7*24*time.Hour)) {
		t.Fatalf("scheduled user = %#v", user)
	}
	var jobKind, jobState, runAfter string
	if err := db.Reader().QueryRow(`SELECT kind, state, run_after FROM jobs WHERE id = (SELECT job_id FROM account_deletions WHERE user_id = ?)`, source.ID).Scan(&jobKind, &jobState, &runAfter); err != nil {
		t.Fatal(err)
	}
	if jobKind != DeletionJobKind || jobState != "queued" || runAfter != now.Add(7*24*time.Hour).Format(time.RFC3339Nano) {
		t.Fatalf("job kind=%q state=%q run_after=%q", jobKind, jobState, runAfter)
	}

	identity := &fakeDeletionIdentity{db: db.Writer(), sourceID: source.ID}
	processor := NewDeletionProcessor(repository, identity, fakeStagingCleaner{}, audit.NewSQLRecorder(db.Writer()))
	if err := processor.Process(context.Background(), source.ID); !errors.Is(err, ErrDeletionNotDue) {
		t.Fatalf("early process error = %v", err)
	}
	now = now.Add(7 * 24 * time.Hour)
	if err := processor.Process(context.Background(), source.ID); err != nil {
		t.Fatal(err)
	}
	if identity.calls != 1 || identity.sawLocalState != StateDeleted {
		t.Fatalf("identity calls=%d saw state=%q", identity.calls, identity.sawLocalState)
	}
	deleted, err := repository.GetUserByID(context.Background(), source.ID)
	if err != nil || deleted.State != StateDeleted || deleted.WorkOSUserID != "" || deleted.RootNodeID != "" || deleted.Email != "deleted-"+compactID(source.ID)+"@deleted.invalid" {
		t.Fatalf("deleted = %#v, err = %v", deleted, err)
	}
	var rootParent, rootOwner, rootName, blobOwner string
	if err := db.Reader().QueryRow(`SELECT parent_id, owner_id, name FROM nodes WHERE id = ?`, source.RootNodeID).Scan(&rootParent, &rootOwner, &rootName); err != nil {
		t.Fatal(err)
	}
	if rootParent != target.RootNodeID || rootOwner != target.ID || rootName != "Transferred from @source-transfer" {
		t.Fatalf("transferred root parent=%q owner=%q name=%q", rootParent, rootOwner, rootName)
	}
	if err := db.Reader().QueryRow(`SELECT owner_id FROM blobs WHERE id = 'blob-source-transfer'`).Scan(&blobOwner); err != nil || blobOwner != target.ID {
		t.Fatalf("blob owner=%q err=%v", blobOwner, err)
	}
	var used int64
	var state string
	if err := db.Reader().QueryRow(`SELECT used_bytes, state FROM users WHERE id = ?`, target.ID).Scan(&used, &state); err != nil || used != 80 || state != string(StateActive) {
		t.Fatalf("target used=%d state=%q err=%v", used, state, err)
	}
	assertDeletionAuditActions(t, db.Reader(), source.ID, "user.deletion_scheduled", "user.deletion_local_completed", "user.deleted")
	if err := processor.Process(context.Background(), source.ID); err != nil || identity.calls != 1 {
		t.Fatalf("idempotent retry err=%v calls=%d", err, identity.calls)
	}
}

func TestDeletionPurgeQueuesBlobGCAndRetriesTransientIdentityFailure(t *testing.T) {
	db := openDeletionTestDB(t)
	repository := NewRepository(db.Writer())
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	repository.now = func() time.Time { return now }
	admin := createDeletionUser(t, repository, "admin-purge", RoleSuperadmin, StateActive)
	source := createDeletionUser(t, repository, "source-purge", RoleMember, StateActive)
	completeWorkOS(t, repository, source.ID, "workos_purge")
	seedDeletionFile(t, db.Writer(), source, 120)
	service := NewService(repository, nil, nil, audit.NewSQLRecorder(db.Writer()))
	service.now = func() time.Time { return now }
	if _, err := service.ScheduleDeletion(context.Background(), source.ID, DeletionPlan{Mode: DeletionPurge}, MutationContext{ActorID: admin.ID}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(7 * 24 * time.Hour)
	identity := &fakeDeletionIdentity{db: db.Writer(), sourceID: source.ID, failures: 1}
	processor := NewDeletionProcessor(repository, identity, fakeStagingCleaner{}, audit.NewSQLRecorder(db.Writer()))
	if err := processor.Process(context.Background(), source.ID); err == nil {
		t.Fatal("transient WorkOS failure was ignored")
	}
	deletion, err := repository.GetDeletion(context.Background(), source.ID)
	if err != nil || deletion.State != "local_complete" || identity.calls != 1 {
		t.Fatalf("deletion=%#v calls=%d err=%v", deletion, identity.calls, err)
	}
	var nodeCount, versionCount int
	if err := db.Reader().QueryRow(`SELECT COUNT(*) FROM nodes WHERE owner_id = ?`, source.ID).Scan(&nodeCount); err != nil || nodeCount != 0 {
		t.Fatalf("nodes=%d err=%v", nodeCount, err)
	}
	if err := db.Reader().QueryRow(`SELECT COUNT(*) FROM file_versions WHERE blob_id = 'blob-source-purge'`).Scan(&versionCount); err != nil || versionCount != 0 {
		t.Fatalf("versions=%d err=%v", versionCount, err)
	}
	var refs int
	var blobState, deleteAfter string
	if err := db.Reader().QueryRow(`SELECT ref_count, state, delete_after FROM blobs WHERE id = 'blob-source-purge'`).Scan(&refs, &blobState, &deleteAfter); err != nil || refs != 0 || blobState != "deleting" || deleteAfter != now.Add(24*time.Hour).Format(time.RFC3339Nano) {
		t.Fatalf("blob refs=%d state=%q delete_after=%q err=%v", refs, blobState, deleteAfter, err)
	}
	if err := processor.Process(context.Background(), source.ID); err != nil || identity.calls != 2 {
		t.Fatalf("retry err=%v calls=%d", err, identity.calls)
	}
	deletion, _ = repository.GetDeletion(context.Background(), source.ID)
	if deletion.State != "completed" {
		t.Fatalf("completed deletion = %#v", deletion)
	}
}

func TestDeletionRestoreCancelsJobAndExpiredWindowCannotRestore(t *testing.T) {
	db := openDeletionTestDB(t)
	repository := NewRepository(db.Writer())
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	repository.now = func() time.Time { return now }
	admin := createDeletionUser(t, repository, "admin-restore", RoleSuperadmin, StateActive)
	source := createDeletionUser(t, repository, "source-restore", RoleMember, StateActive)
	service := NewService(repository, nil, nil, audit.NopRecorder{})
	service.now = func() time.Time { return now }
	if _, err := service.ScheduleDeletion(context.Background(), source.ID, DeletionPlan{Mode: DeletionPurge}, MutationContext{ActorID: admin.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RestoreUser(context.Background(), source.ID, MutationContext{ActorID: admin.ID}); err != nil {
		t.Fatal(err)
	}
	deletion, _ := repository.GetDeletion(context.Background(), source.ID)
	if deletion.State != "cancelled" {
		t.Fatalf("deletion state = %q", deletion.State)
	}
	var jobState, lastError string
	if err := db.Reader().QueryRow(`SELECT state, COALESCE(last_error, '') FROM jobs WHERE id = ?`, deletion.JobID).Scan(&jobState, &lastError); err != nil || jobState != "completed" || lastError != "cancelled by account restore" {
		t.Fatalf("job state=%q error=%q query=%v", jobState, lastError, err)
	}
	if err := NewDeletionProcessor(repository, &fakeDeletionIdentity{}, fakeStagingCleaner{}, audit.NopRecorder{}).Process(context.Background(), source.ID); err != nil {
		t.Fatalf("cancelled process = %v", err)
	}
	if _, err := service.ScheduleDeletion(context.Background(), source.ID, DeletionPlan{Mode: DeletionPurge}, MutationContext{ActorID: admin.ID}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(7 * 24 * time.Hour)
	if _, err := service.RestoreUser(context.Background(), source.ID, MutationContext{ActorID: admin.ID}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expired restore error = %v", err)
	}
}

func TestDeletionFinalSuperadminAndPlanValidation(t *testing.T) {
	db := openDeletionTestDB(t)
	repository := NewRepository(db.Writer())
	admin := createDeletionUser(t, repository, "only-admin", RoleSuperadmin, StateActive)
	service := NewService(repository, nil, nil, audit.NopRecorder{})
	if _, err := service.ScheduleDeletion(context.Background(), admin.ID, DeletionPlan{Mode: DeletionPurge}, MutationContext{ActorID: admin.ID}); !errors.Is(err, ErrLastSuperadmin) {
		t.Fatalf("final superadmin deletion error = %v", err)
	}
	member := createDeletionUser(t, repository, "plan-member", RoleMember, StateActive)
	if _, err := service.ScheduleDeletion(context.Background(), member.ID, DeletionPlan{}, MutationContext{ActorID: admin.ID}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing plan error = %v", err)
	}
}

func openDeletionTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(context.Background(), database.Config{Path: filepath.Join(t.TempDir(), "arca.sqlite3"), Migrations: migrations.Files})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func createDeletionUser(t *testing.T, repository *Repository, username string, role Role, state State) *User {
	t.Helper()
	user, err := repository.CreateUser(context.Background(), CreateUserParams{
		Username: username, Email: username + "@example.com", Role: role, State: state,
		QuotaBytes: 1_000, Policy: DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func completeWorkOS(t *testing.T, repository *Repository, userID, workosID string) {
	t.Helper()
	if _, err := repository.db.Exec(`UPDATE users SET workos_user_id = ? WHERE id = ?`, workosID, userID); err != nil {
		t.Fatal(err)
	}
}

func seedDeletionFile(t *testing.T, db *sql.DB, owner *User, size int64) {
	t.Helper()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	fileID := "file-" + owner.Username
	blobID := "blob-" + owner.Username
	versionID := "version-" + owner.Username
	if _, err := db.Exec(`INSERT INTO blobs(id, owner_id, storage_key, size_bytes, sha256, state, ref_count, created_at)
		VALUES (?, ?, ?, ?, ?, 'ready', 1, ?)`, blobID, owner.ID, "opaque-"+owner.Username, size, fmt.Sprintf("%064d", 1), stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO nodes(id, owner_id, parent_id, kind, name, name_key, mime_type, size_bytes, created_by, created_at, updated_at)
		VALUES (?, ?, ?, 'file', 'data.bin', 'data.bin', 'application/octet-stream', ?, ?, ?, ?)`, fileID, owner.ID, owner.RootNodeID, size, owner.ID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO file_versions(id, node_id, blob_id, sequence, size_bytes, sha256, mime_type, created_by, created_at)
		VALUES (?, ?, ?, 1, ?, ?, 'application/octet-stream', ?, ?)`, versionID, fileID, blobID, size, fmt.Sprintf("%064d", 1), owner.ID, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE nodes SET current_version_id = ? WHERE id = ?`, versionID, fileID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE users SET used_bytes = ? WHERE id = ?`, size, owner.ID); err != nil {
		t.Fatal(err)
	}
}

type fakeDeletionIdentity struct {
	db            *sql.DB
	sourceID      string
	calls         int
	failures      int
	sawLocalState State
}

func (f *fakeDeletionIdentity) DeleteUser(_ context.Context, _ string) error {
	f.calls++
	if f.db != nil {
		var state string
		if err := f.db.QueryRow(`SELECT state FROM users WHERE id = ?`, f.sourceID).Scan(&state); err == nil {
			f.sawLocalState = State(state)
		}
	}
	if f.calls <= f.failures {
		return errors.New("temporary WorkOS outage")
	}
	return nil
}

type fakeStagingCleaner struct{}

func (fakeStagingCleaner) RemoveStaging(string) error { return nil }

func compactID(value string) string {
	result := ""
	for _, char := range value {
		if char != '-' {
			result += string(char)
		}
	}
	return result
}

func assertDeletionAuditActions(t *testing.T, db *sql.DB, userID string, expected ...string) {
	t.Helper()
	rows, err := db.Query(`SELECT action FROM audit_events WHERE target_id = ? ORDER BY created_at, id`, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, action)
	}
	if fmt.Sprint(actions) != fmt.Sprint(expected) {
		t.Fatalf("audit actions = %v, want %v", actions, expected)
	}
}
