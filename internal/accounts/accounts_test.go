package accounts

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"arca/internal/audit"
	"arca/internal/database"
	"arca/migrations"
)

func TestNormalizeIdentity(t *testing.T) {
	t.Parallel()
	username, key, err := NormalizeUsername("  Alice.Example  ")
	if err != nil {
		t.Fatal(err)
	}
	if username != "Alice.Example" || key != "alice.example" {
		t.Fatalf("username = %q, key = %q", username, key)
	}
	email, emailKey, err := NormalizeEmail("Alice@Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if email != "Alice@Example.COM" || emailKey != "alice@example.com" {
		t.Fatalf("email = %q, key = %q", email, emailKey)
	}
	for _, invalid := range []string{"ab", "-alice", "alice bob", "alice/bob"} {
		if _, _, err := NormalizeUsername(invalid); err == nil {
			t.Errorf("username %q unexpectedly accepted", invalid)
		}
	}
}

func TestAccessRequestStatusAndApproval(t *testing.T) {
	db := openTestDB(t)
	repository := NewRepository(db.Writer())
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	codec, err := NewStatusTokenCodec(secret)
	if err != nil {
		t.Fatal(err)
	}
	identity := &fakeIdentityProvider{}
	service := NewService(repository, identity, codec, audit.NopRecorder{})
	ctx := context.Background()

	admin, err := service.BootstrapSuperadmin(ctx, CreateUserParams{
		Username: "admin", Email: "admin@example.com", Role: RoleSuperadmin,
		QuotaBytes: 10_000, Policy: DefaultPolicy(),
	}, MutationContext{})
	if err != nil {
		t.Fatal(err)
	}
	request, err := service.RequestAccess(ctx, CreateAccessRequestParams{
		Username: "member", Email: "member@example.com", Reason: "Need access",
	}, MutationContext{})
	if err != nil {
		t.Fatal(err)
	}
	status, err := service.RequestStatus(ctx, request.StatusToken)
	if err != nil || status.State != AccessRequestPending {
		t.Fatalf("status = %#v, err = %v", status, err)
	}
	if _, err := service.RequestStatus(ctx, request.StatusToken+"x"); !errors.Is(err, ErrInvalidStatusToken) {
		t.Fatalf("invalid status token error = %v", err)
	}
	member, err := service.ApproveAccessRequest(ctx, ReserveApprovalParams{
		RequestID: request.Request.ID, QuotaBytes: 1_000, Policy: DefaultPolicy(),
	}, "approved", MutationContext{ActorID: admin.ID})
	if err != nil {
		t.Fatal(err)
	}
	if member.State != StateActive || member.WorkOSUserID == "" {
		t.Fatalf("member = %#v", member)
	}
	if identity.calls != 2 { // bootstrap plus member approval
		t.Fatalf("identity reconciliation calls = %d", identity.calls)
	}
	status, err = service.RequestStatus(ctx, request.StatusToken)
	if err != nil || status.State != AccessRequestApproved || status.ApprovedUserID != member.ID {
		t.Fatalf("approved status = %#v, err = %v", status, err)
	}
}

func TestLastActiveSuperadminInvariant(t *testing.T) {
	db := openTestDB(t)
	repository := NewRepository(db.Writer())
	ctx := context.Background()
	admin, err := repository.CreateUser(ctx, CreateUserParams{
		Username: "admin", Email: "admin@example.com", Role: RoleSuperadmin,
		State: StateActive, QuotaBytes: 1, Policy: DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.SetState(ctx, admin.ID, StateSuspended, nil); !errors.Is(err, ErrLastSuperadmin) {
		t.Fatalf("suspend final superadmin error = %v", err)
	}
	if _, err := repository.SetRole(ctx, admin.ID, RoleMember); !errors.Is(err, ErrLastSuperadmin) {
		t.Fatalf("demote final superadmin error = %v", err)
	}
	second, err := repository.CreateUser(ctx, CreateUserParams{
		Username: "second-admin", Email: "second@example.com", Role: RoleSuperadmin,
		State: StateActive, QuotaBytes: 1, Policy: DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.SetState(ctx, admin.ID, StateSuspended, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.SetRole(ctx, second.ID, RoleMember); !errors.Is(err, ErrLastSuperadmin) {
		t.Fatalf("demote remaining active superadmin error = %v", err)
	}
}

func TestSuspensionRevokesSharesPublicCodesTokensAndSupportAccess(t *testing.T) {
	db := openTestDB(t)
	repository := NewRepository(db.Writer())
	now := time.Now().UTC()
	repository.now = func() time.Time { return now }
	admin, err := repository.CreateUser(context.Background(), CreateUserParams{Username: "admin-revoke", Email: "admin-revoke@example.com", Role: RoleSuperadmin, State: StateActive, QuotaBytes: 1 << 20, Policy: DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	member, err := repository.CreateUser(context.Background(), CreateUserParams{Username: "member-revoke", Email: "member-revoke@example.com", Role: RoleMember, State: StateActive, QuotaBytes: 1 << 20, Policy: DefaultPolicy()})
	if err != nil {
		t.Fatal(err)
	}
	rootID := "0198a000-0000-7000-8000-00000000aa01"
	nodeID := "0198a000-0000-7000-8000-00000000aa02"
	stamp := now.Format(time.RFC3339Nano)
	if _, err := db.Writer().Exec(`INSERT INTO nodes(id, owner_id, parent_id, kind, name, name_key, created_by, created_at, updated_at) VALUES
		(?, ?, NULL, 'folder', '', '', ?, ?, ?),
		(?, ?, ?, 'folder', 'Shared', 'shared', ?, ?, ?)`, rootID, member.ID, member.ID, stamp, stamp, nodeID, member.ID, rootID, member.ID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec(`UPDATE users SET root_node_id = ? WHERE id = ?`, rootID, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec(`INSERT INTO shares(id, owner_id, permission, created_at, updated_at) VALUES('share-revoke', ?, 'viewer', ?, ?)`, member.ID, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec(`INSERT INTO public_shares(id, owner_id, code_hash, expires_at, redemption_limit, created_at) VALUES('public-revoke', ?, x'01', ?, 3, ?)`, member.ID, now.Add(time.Hour).Format(time.RFC3339Nano), stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec(`INSERT INTO api_tokens(id, user_id, name, token_prefix, token_hash, scopes, created_at) VALUES('token-revoke', ?, 'test', 'arca_pat_fixture', x'02', '["files:read"]', ?)`, member.ID, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec(`INSERT INTO support_access(id, actor_id, target_user_id, reason, expires_at, created_at) VALUES('support-revoke', ?, ?, 'Investigating member files', ?, ?)`, admin.ID, member.ID, now.Add(time.Hour).Format(time.RFC3339Nano), stamp); err != nil {
		t.Fatal(err)
	}

	service := NewService(repository, &fakeIdentityProvider{}, nil, audit.NopRecorder{})
	if _, err := service.SuspendUser(context.Background(), member.ID, MutationContext{ActorID: admin.ID}); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		query string
		args  []any
	}{
		{`SELECT revoked_at FROM shares WHERE id = 'share-revoke'`, nil},
		{`SELECT revoked_at FROM public_shares WHERE id = 'public-revoke'`, nil},
		{`SELECT revoked_at FROM api_tokens WHERE id = 'token-revoke'`, nil},
		{`SELECT revoked_at FROM support_access WHERE id = 'support-revoke'`, nil},
	}
	for _, check := range checks {
		var revoked sql.NullString
		if err := db.Reader().QueryRow(check.query, check.args...).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
		if !revoked.Valid {
			t.Fatalf("revocation was not applied by %q", check.query)
		}
	}
}

func TestDeletedExternalIdentitySuspendsEvenFinalSuperadmin(t *testing.T) {
	db := openTestDB(t)
	repository := NewRepository(db.Writer())
	admin, err := repository.CreateUser(context.Background(), CreateUserParams{
		Username: "admin", Email: "admin@example.com", Role: RoleSuperadmin,
		State: StateProvisioning, QuotaBytes: 1, Policy: DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CompleteProvisioning(context.Background(), admin.ID, "workos_admin"); err != nil {
		t.Fatal(err)
	}
	admin, err = repository.SuspendIdentityDeleted(context.Background(), "workos_admin")
	if err != nil || admin.State != StateSuspended {
		t.Fatalf("admin = %#v, err = %v", admin, err)
	}
}

func TestQuotaUpdateSetsAndClearsOverQuota(t *testing.T) {
	db := openTestDB(t)
	repository := NewRepository(db.Writer())
	ctx := context.Background()
	user, err := repository.CreateUser(ctx, CreateUserParams{
		Username: "member", Email: "member@example.com", Role: RoleMember,
		State: StateActive, QuotaBytes: 1_000, Policy: DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec(`UPDATE users SET used_bytes = 750 WHERE id = ?`, user.ID); err != nil {
		t.Fatal(err)
	}
	user, err = repository.UpdatePolicyAndQuota(ctx, user.ID, 500, false, DefaultPolicy())
	if err != nil || user.State != StateOverQuota {
		t.Fatalf("over-quota user = %#v, err = %v", user, err)
	}
	user, err = repository.UpdatePolicyAndQuota(ctx, user.ID, 1_000, false, DefaultPolicy())
	if err != nil || user.State != StateActive {
		t.Fatalf("restored quota user = %#v, err = %v", user, err)
	}
}

func TestPurgeRejectedAccessRequestsRetainsThirtyDays(t *testing.T) {
	db := openTestDB(t)
	repository := NewRepository(db.Writer())
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	admin, err := repository.CreateUser(context.Background(), CreateUserParams{
		Username: "retention-admin", Email: "retention-admin@example.com", Role: RoleSuperadmin,
		State: StateActive, QuotaBytes: 1, Policy: DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	insert := func(id string, decided time.Time) {
		t.Helper()
		if _, err := db.Writer().Exec(`INSERT INTO access_requests
			(id, username, username_key, email, email_key, state, status_token_hash, requested_at, decided_at, decided_by)
			VALUES (?, ?, ?, ?, ?, 'rejected', ?, ?, ?, ?)`, id, id, id, id+"@example.com", id+"@example.com", []byte(id), decided.Add(-time.Hour).Format(time.RFC3339Nano), decided.Format(time.RFC3339Nano), admin.ID); err != nil {
			t.Fatal(err)
		}
	}
	insert("old-request", now.Add(-31*24*time.Hour))
	insert("recent-request", now.Add(-29*24*time.Hour))
	deleted, err := repository.PurgeRejectedAccessRequests(context.Background(), now.Add(-30*24*time.Hour))
	if err != nil || deleted != 1 {
		t.Fatalf("deleted=%d err=%v", deleted, err)
	}
	var remaining string
	if err := db.Reader().QueryRow(`SELECT id FROM access_requests`).Scan(&remaining); err != nil || remaining != "recent-request" {
		t.Fatalf("remaining=%q err=%v", remaining, err)
	}
}

func TestSupportAccessIsShortLivedAndAuditable(t *testing.T) {
	db := openTestDB(t)
	repository := NewRepository(db.Writer())
	ctx := context.Background()
	admin, err := repository.CreateUser(ctx, CreateUserParams{
		Username: "admin", Email: "admin@example.com", Role: RoleSuperadmin,
		State: StateActive, QuotaBytes: 1, Policy: DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	member, err := repository.CreateUser(ctx, CreateUserParams{
		Username: "member", Email: "member@example.com", Role: RoleMember,
		State: StateActive, QuotaBytes: 1, Policy: DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(repository, &fakeIdentityProvider{}, nil, audit.NewSQLRecorder(db.Writer()))
	access, err := service.GrantSupportAccess(ctx, member.ID, "Investigating preview failure", MutationContext{ActorID: admin.ID, RequestID: "request_1"})
	if err != nil {
		t.Fatal(err)
	}
	if lifetime := access.ExpiresAt.Sub(access.CreatedAt); lifetime < 14*time.Minute+59*time.Second || lifetime > 15*time.Minute {
		t.Fatalf("support lifetime = %s", access.ExpiresAt.Sub(access.CreatedAt))
	}
	active, err := repository.GetActiveSupportAccess(ctx, admin.ID)
	if err != nil || active.ID != access.ID {
		t.Fatalf("active support = %#v, err = %v", active, err)
	}
	if _, err := service.RevokeSupportAccess(ctx, access.ID, MutationContext{ActorID: admin.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.GetActiveSupportAccess(ctx, admin.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked support lookup error = %v", err)
	}
	var count int
	if err := db.Reader().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE target_id = ?`, access.ID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("audit count = %d, err = %v", count, err)
	}
}

type fakeIdentityProvider struct{ calls int }

func (f *fakeIdentityProvider) ReconcileUser(_ context.Context, request IdentityRequest) (ExternalIdentity, error) {
	f.calls++
	return ExternalIdentity{ID: "workos_" + request.ArcaUserID, Email: request.Email}, nil
}

func openTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(context.Background(), database.Config{
		Path: filepath.Join(t.TempDir(), "arca.sqlite3"), Migrations: migrations.Files,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
