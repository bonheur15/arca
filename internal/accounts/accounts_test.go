package accounts

import (
	"context"
	"crypto/rand"
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
	if access.ExpiresAt.Sub(access.CreatedAt) != 15*time.Minute {
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
