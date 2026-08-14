package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"arca/internal/accounts"
	"arca/internal/audit"
	"arca/internal/database"
	"arca/migrations"
)

func TestMagicAuthFlowAndChallengeReplay(t *testing.T) {
	db := openAuthTestDB(t)
	repository := accounts.NewRepository(db.Writer())
	user, err := repository.CreateUser(context.Background(), accounts.CreateUserParams{
		Username: "alice", Email: "alice@example.com", Role: accounts.RoleMember,
		State: accounts.StateProvisioning, QuotaBytes: 1_000, Policy: accounts.DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CompleteProvisioning(context.Background(), user.ID, "workos_alice"); err != nil {
		t.Fatal(err)
	}
	secret := randomSecret(t)
	challenges, err := NewChallengeStore(db.Writer(), secret)
	if err != nil {
		t.Fatal(err)
	}
	provider := &fakeProvider{workosUserID: "workos_alice", email: "alice@example.com"}
	service, err := NewService(repository, challenges, provider, db.Writer(), "cookie-password", secret, audit.NopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	start, err := service.StartMagic(context.Background(), MagicStartRequest{
		Email: "ALICE@example.com", IPAddress: "192.0.2.1", UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if provider.start.Email != "ALICE@example.com" && provider.start.Email != "alice@example.com" {
		t.Fatalf("provider start email = %q", provider.start.Email)
	}
	verified, err := service.VerifyMagic(context.Background(), start.ChallengeToken, "123456")
	if err != nil {
		t.Fatal(err)
	}
	if verified.User.ID != user.ID || verified.SessionID != "session_123" || verified.SealedSession == "" || verified.CSRFToken == "" {
		t.Fatalf("verified = %#v", verified)
	}
	if provider.verify.IPAddress != "192.0.2.1" || provider.verify.UserAgent != "test-agent" {
		t.Fatalf("verification did not preserve original request data: %#v", provider.verify)
	}
	if _, err := service.VerifyMagic(context.Background(), start.ChallengeToken, "123456"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("challenge replay error = %v", err)
	}
	principal, err := service.Authenticate(context.Background(), verified.SealedSession)
	if err != nil || principal.User.ID != user.ID {
		t.Fatalf("principal = %#v, err = %v", principal, err)
	}
}

func TestUnknownMagicEmailDoesNotCallProvider(t *testing.T) {
	db := openAuthTestDB(t)
	repository := accounts.NewRepository(db.Writer())
	secret := randomSecret(t)
	challenges, _ := NewChallengeStore(db.Writer(), secret)
	provider := &fakeProvider{}
	service, _ := NewService(repository, challenges, provider, db.Writer(), "cookie-password", secret, audit.NopRecorder{})
	start, err := service.StartMagic(context.Background(), MagicStartRequest{Email: "unknown@example.com"})
	if err != nil || start.ChallengeToken == "" {
		t.Fatalf("start = %#v, err = %v", start, err)
	}
	if provider.startCalls != 0 {
		t.Fatalf("provider start calls = %d", provider.startCalls)
	}
	if _, err := service.VerifyMagic(context.Background(), start.ChallengeToken, "123456"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("verify unknown error = %v", err)
	}
}

func TestCookieAndCSRFProperties(t *testing.T) {
	secret := randomSecret(t)
	token, err := GenerateCSRFToken(secret, "session_123")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCSRFToken(secret, "session_123", token, token); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCSRFToken(secret, "session_other", token, token); !errors.Is(err, ErrInvalidCSRF) {
		t.Fatalf("other-session CSRF error = %v", err)
	}
	recorder := httptest.NewRecorder()
	policy := DefaultCookiePolicy(true)
	policy.SetSession(recorder, "sealed", time.Now().Add(time.Hour))
	cookie := recorder.Result().Cookies()[0]
	if cookie.Name != ProductionSessionCookieName || !cookie.HttpOnly || !cookie.Secure || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %#v", cookie)
	}
}

func TestPersonalAccessTokenLifecycle(t *testing.T) {
	db := openAuthTestDB(t)
	repository := accounts.NewRepository(db.Writer())
	user, err := repository.CreateUser(context.Background(), accounts.CreateUserParams{
		Username: "alice", Email: "alice@example.com", Role: accounts.RoleMember,
		State: accounts.StateActive, QuotaBytes: 1_000, Policy: accounts.DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewTokenService(db.Writer(), repository, randomSecret(t), audit.NopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Create(context.Background(), user.ID, "CLI", []Scope{ScopeFilesRead}, nil, accounts.MutationContext{ActorID: user.ID})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Token, "arca_pat_") || strings.Contains(created.Prefix, created.Token) {
		t.Fatalf("token = %q prefix = %q", created.Token, created.Prefix)
	}
	principal, err := service.Authenticate(context.Background(), created.Token)
	if err != nil || !principal.HasScope(ScopeFilesRead) || principal.HasScope(ScopeFilesWrite) {
		t.Fatalf("token principal = %#v, err = %v", principal, err)
	}
	if err := service.Revoke(context.Background(), created.ID, user.ID, accounts.MutationContext{ActorID: user.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(context.Background(), created.Token); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("revoked token error = %v", err)
	}
}

func TestEventReconcilerUpdatesIdentityRevokesSessionAndSuspends(t *testing.T) {
	db := openAuthTestDB(t)
	repository := accounts.NewRepository(db.Writer())
	user, err := repository.CreateUser(context.Background(), accounts.CreateUserParams{
		Username: "alice", Email: "alice@example.com", Role: accounts.RoleMember,
		State: accounts.StateProvisioning, QuotaBytes: 1_000, Policy: accounts.DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CompleteProvisioning(context.Background(), user.ID, "workos_alice"); err != nil {
		t.Fatal(err)
	}
	secret := randomSecret(t)
	challenges, _ := NewChallengeStore(db.Writer(), secret)
	provider := &fakeProvider{}
	authService, _ := NewService(repository, challenges, provider, db.Writer(), "cookie-password", secret, audit.NopRecorder{})
	source := &fakeEventSource{events: []IdentityEvent{
		{ID: "evt_1", Kind: EventUserUpdated, WorkOSUserID: "workos_alice", Email: "alice.new@example.com"},
		{ID: "evt_2", Kind: EventSessionRevoked, WorkOSUserID: "workos_alice", SessionID: "session_1", ExpiresAt: time.Now().Add(time.Hour)},
		{ID: "evt_3", Kind: EventUserDeleted, WorkOSUserID: "workos_alice"},
	}, next: "evt_3"}
	reconciler, err := NewEventReconciler(db.Writer(), repository, authService, source, audit.NopRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	count, err := reconciler.PollOnce(context.Background(), 100)
	if err != nil || count != 3 {
		t.Fatalf("poll count = %d, err = %v", count, err)
	}
	updated, err := repository.GetUserByID(context.Background(), user.ID)
	if err != nil || updated.Email != "alice.new@example.com" || updated.State != accounts.StateSuspended {
		t.Fatalf("updated user = %#v, err = %v", updated, err)
	}
	revoked, err := authService.isLocallyRevoked(context.Background(), "session_1")
	if err != nil || !revoked {
		t.Fatalf("revoked = %t, err = %v", revoked, err)
	}
	var cursor string
	if err := db.Reader().QueryRow(`SELECT cursor FROM workos_event_cursor WHERE singleton = 1`).Scan(&cursor); err != nil || cursor != "evt_3" {
		t.Fatalf("cursor = %q, err = %v", cursor, err)
	}
}

func TestRevokeSessionVerifiesOwnership(t *testing.T) {
	db := openAuthTestDB(t)
	repository := accounts.NewRepository(db.Writer())
	user, err := repository.CreateUser(context.Background(), accounts.CreateUserParams{
		Username: "alice", Email: "alice@example.com", Role: accounts.RoleMember,
		State: accounts.StateProvisioning, QuotaBytes: 1_000, Policy: accounts.DefaultPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CompleteProvisioning(context.Background(), user.ID, "workos_alice"); err != nil {
		t.Fatal(err)
	}
	secret := randomSecret(t)
	challenges, _ := NewChallengeStore(db.Writer(), secret)
	provider := &fakeProvider{sessions: []RemoteSession{{ID: "own_session", UserID: "workos_alice", ExpiresAt: time.Now().Add(time.Hour)}}}
	service, _ := NewService(repository, challenges, provider, db.Writer(), "cookie-password", secret, audit.NopRecorder{})
	mutation := accounts.MutationContext{ActorID: user.ID}
	if err := service.RevokeSession(context.Background(), "other_session", user.ID, time.Now().Add(time.Minute), mutation); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign session revocation error = %v", err)
	}
	if len(provider.revoked) != 0 {
		t.Fatalf("foreign session reached provider: %#v", provider.revoked)
	}
	if err := service.RevokeSession(context.Background(), "own_session", user.ID, time.Now().Add(time.Minute), mutation); err != nil {
		t.Fatal(err)
	}
	if len(provider.revoked) != 1 || provider.revoked[0] != "own_session" {
		t.Fatalf("revoked sessions = %#v", provider.revoked)
	}
}

func TestMemoryLimiter(t *testing.T) {
	limiter := NewMemoryLimiter()
	now := time.Date(2026, time.August, 14, 0, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	for range 2 {
		allowed, _ := limiter.Allow(context.Background(), "email", 2, time.Minute)
		if !allowed {
			t.Fatal("attempt unexpectedly denied")
		}
	}
	allowed, retry := limiter.Allow(context.Background(), "email", 2, time.Minute)
	if allowed || retry != time.Minute {
		t.Fatalf("limited = %t, retry = %s", !allowed, retry)
	}
	now = now.Add(time.Minute)
	allowed, _ = limiter.Allow(context.Background(), "email", 2, time.Minute)
	if !allowed {
		t.Fatal("attempt remained denied after window")
	}
}

type fakeProvider struct {
	startCalls   int
	start        MagicStartRequest
	verify       MagicVerifyRequest
	workosUserID string
	email        string
	revoked      []string
	sessions     []RemoteSession
}

func (f *fakeProvider) ListSessions(_ context.Context, _ string, _ int) ([]RemoteSession, error) {
	return f.sessions, nil
}

type fakeEventSource struct {
	events []IdentityEvent
	next   string
	after  string
}

func (f *fakeEventSource) ListIdentityEvents(_ context.Context, after string, _ int) ([]IdentityEvent, string, error) {
	f.after = after
	return f.events, f.next, nil
}

func (f *fakeProvider) SendMagic(_ context.Context, request MagicStartRequest) (MagicChallenge, error) {
	f.startCalls++
	f.start = request
	return MagicChallenge{
		ID: "magic_123", UserID: f.workosUserID, Email: f.email,
		ExpiresAt: time.Now().Add(10 * time.Minute), RadarAuthAttemptID: "radar_123",
	}, nil
}

func (f *fakeProvider) VerifyMagic(_ context.Context, request MagicVerifyRequest) (RemoteAuthentication, error) {
	f.verify = request
	return RemoteAuthentication{
		WorkOSUserID: f.workosUserID, Email: f.email,
		AccessToken: fakeJWT("session_123", time.Now().Add(time.Hour)), RefreshToken: "refresh",
	}, nil
}

func (f *fakeProvider) SealSession(authentication RemoteAuthentication, _ string) (string, error) {
	encoded, _ := json.Marshal(authentication)
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func (f *fakeProvider) InspectSession(sealed, _ string) (SessionInspection, error) {
	encoded, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		return SessionInspection{}, err
	}
	var authentication RemoteAuthentication
	if err := json.Unmarshal(encoded, &authentication); err != nil {
		return SessionInspection{}, err
	}
	return SessionInspection{Authenticated: true, WorkOSUserID: authentication.WorkOSUserID, SessionID: "session_123"}, nil
}

func (f *fakeProvider) RefreshSession(context.Context, string, string) (SessionRefresh, error) {
	return SessionRefresh{}, nil
}

func (f *fakeProvider) RevokeSession(_ context.Context, sessionID string) error {
	f.revoked = append(f.revoked, sessionID)
	return nil
}

func fakeJWT(sessionID string, expiresAt time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload, _ := json.Marshal(map[string]any{"sid": sessionID, "exp": expiresAt.Unix()})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func randomSecret(t *testing.T) []byte {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	return secret
}

func openAuthTestDB(t *testing.T) *database.DB {
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
