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

type fakeProvider struct {
	startCalls   int
	start        MagicStartRequest
	verify       MagicVerifyRequest
	workosUserID string
	email        string
	revoked      []string
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
