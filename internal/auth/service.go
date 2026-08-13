package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"arca/internal/accounts"
	"arca/internal/audit"
)

var magicCodePattern = regexp.MustCompile(`^[0-9]{6}$`)

type AuthService struct {
	accounts       *accounts.Repository
	challenges     *ChallengeStore
	provider       Provider
	audit          audit.Recorder
	cookiePassword string
	csrfSecret     []byte
	db             *sql.DB
	limiter        AttemptLimiter
	now            func() time.Time
}

func NewService(accountRepository *accounts.Repository, challenges *ChallengeStore, provider Provider, db *sql.DB, cookiePassword string, csrfSecret []byte, recorder audit.Recorder) (*AuthService, error) {
	if accountRepository == nil || challenges == nil || provider == nil || db == nil {
		return nil, errors.New("auth: account repository, challenge store, provider, and database are required")
	}
	if cookiePassword == "" {
		return nil, errors.New("auth: cookie password is required")
	}
	if len(csrfSecret) < 32 {
		return nil, errors.New("auth: csrf secret must contain at least 32 bytes")
	}
	if recorder == nil {
		recorder = audit.NopRecorder{}
	}
	return &AuthService{
		accounts: accountRepository, challenges: challenges, provider: provider,
		audit: recorder, cookiePassword: cookiePassword,
		csrfSecret: append([]byte(nil), csrfSecret...), db: db, now: time.Now,
		limiter: NewMemoryLimiter(),
	}, nil
}

// SetAttemptLimiter replaces the default single-process limiter, primarily for
// deterministic tests or a future durable implementation.
func (s *AuthService) SetAttemptLimiter(limiter AttemptLimiter) {
	if limiter != nil {
		s.limiter = limiter
	}
}

type MagicStartResult struct {
	ChallengeToken string
	ExpiresAt      time.Time
}

// StartMagic intentionally creates an opaque local challenge even for an
// unknown or inactive email. The HTTP response can therefore remain identical
// without provisioning an arbitrary WorkOS identity.
func (s *AuthService) StartMagic(ctx context.Context, request MagicStartRequest) (*MagicStartResult, error) {
	email, emailKey, err := accounts.NormalizeEmail(request.Email)
	if err != nil {
		return nil, err
	}
	request.Email = email
	if err := s.allowAttempt(ctx, "magic:start:email:"+emailKey, 5, 10*time.Minute); err != nil {
		return nil, err
	}
	if request.IPAddress != "" {
		if err := s.allowAttempt(ctx, "magic:start:ip:"+request.IPAddress, 10, 10*time.Minute); err != nil {
			return nil, err
		}
	}
	expiresAt := s.now().UTC().Add(10 * time.Minute)
	magicID, radarID := "", ""
	user, lookupErr := s.accounts.GetUserByEmail(ctx, email)
	if lookupErr != nil && !errors.Is(lookupErr, accounts.ErrNotFound) {
		return nil, lookupErr
	}
	if lookupErr == nil && user.State.CanAuthenticate() && user.WorkOSUserID != "" {
		remote, sendErr := s.provider.SendMagic(ctx, request)
		if sendErr != nil {
			_ = s.record(ctx, nil, "authentication.magic_start_failed", "user", user.ID, map[string]any{"reason": "provider_error"})
			return nil, sendErr
		}
		_, remoteEmailKey, normalizeErr := accounts.NormalizeEmail(remote.Email)
		if normalizeErr != nil || remote.UserID != user.WorkOSUserID || remoteEmailKey != user.EmailKey {
			_ = s.record(ctx, nil, "authentication.magic_start_failed", "user", user.ID, map[string]any{"reason": "identity_mismatch"})
			return nil, errors.New("auth: identity provider returned a mismatched challenge")
		}
		magicID, radarID = remote.ID, remote.RadarAuthAttemptID
		if remote.ExpiresAt.Before(expiresAt) {
			expiresAt = remote.ExpiresAt
		}
	}
	_, token, err := s.challenges.Create(ctx, emailKey, magicID, radarID, request.IPAddress, request.UserAgent, expiresAt)
	if err != nil {
		return nil, err
	}
	return &MagicStartResult{ChallengeToken: token, ExpiresAt: expiresAt}, nil
}

type MagicVerifyResult struct {
	User          accounts.User
	SealedSession string
	SessionID     string
	CSRFToken     string
}

func (s *AuthService) VerifyMagic(ctx context.Context, challengeToken, code string) (*MagicVerifyResult, error) {
	if !magicCodePattern.MatchString(code) {
		s.recordFailure(ctx, "invalid_code_format")
		return nil, ErrInvalidCredentials
	}
	challenge, err := s.challenges.Get(ctx, challengeToken)
	if err != nil {
		s.recordFailure(ctx, "invalid_challenge")
		return nil, ErrInvalidCredentials
	}
	if err := s.allowAttempt(ctx, "magic:verify:email:"+challenge.EmailKey, 10, 10*time.Minute); err != nil {
		return nil, err
	}
	if challenge.OriginalIPAddress != "" {
		if err := s.allowAttempt(ctx, "magic:verify:ip:"+challenge.OriginalIPAddress, 20, 10*time.Minute); err != nil {
			return nil, err
		}
	}
	if challenge.MagicAuthID == "" {
		s.recordFailure(ctx, "invalid_challenge")
		return nil, ErrInvalidCredentials
	}
	user, err := s.accounts.GetUserByEmail(ctx, challenge.EmailKey)
	if err != nil || !user.State.CanAuthenticate() || user.WorkOSUserID == "" {
		s.recordFailure(ctx, "inactive_account")
		return nil, ErrInvalidCredentials
	}
	authentication, err := s.provider.VerifyMagic(ctx, MagicVerifyRequest{
		Email: user.Email, Code: code, IPAddress: challenge.OriginalIPAddress,
		UserAgent: challenge.OriginalUserAgent, RadarAuthAttemptID: challenge.RadarAuthAttemptID,
	})
	if err != nil {
		s.recordFailure(ctx, "provider_rejected")
		return nil, ErrInvalidCredentials
	}
	_, returnedEmailKey, normalizeErr := accounts.NormalizeEmail(authentication.Email)
	if normalizeErr != nil || authentication.WorkOSUserID != user.WorkOSUserID || returnedEmailKey != user.EmailKey {
		s.recordFailure(ctx, "identity_mismatch")
		return nil, ErrInvalidCredentials
	}
	sealed, err := s.provider.SealSession(authentication, s.cookiePassword)
	if err != nil {
		return nil, err
	}
	inspection, err := s.provider.InspectSession(sealed, s.cookiePassword)
	if err != nil || !inspection.Authenticated || inspection.SessionID == "" || inspection.WorkOSUserID != user.WorkOSUserID {
		return nil, ErrInvalidCredentials
	}
	if err := s.challenges.Consume(ctx, challenge.ID); err != nil {
		_ = s.provider.RevokeSession(ctx, inspection.SessionID)
		return nil, ErrInvalidCredentials
	}
	now := s.now().UTC()
	if err := s.accounts.UpdateLastSignIn(ctx, user.ID, now); err != nil {
		_ = s.provider.RevokeSession(ctx, inspection.SessionID)
		_ = s.revokeLocally(ctx, inspection.SessionID, user.ID, now.Add(30*24*time.Hour))
		return nil, ErrInvalidCredentials
	}
	csrfToken, err := GenerateCSRFToken(s.csrfSecret, inspection.SessionID)
	if err != nil {
		_ = s.provider.RevokeSession(ctx, inspection.SessionID)
		return nil, err
	}
	if err := s.record(ctx, &user.ID, "authentication.magic_succeeded", "session", inspection.SessionID, nil); err != nil {
		_ = s.provider.RevokeSession(ctx, inspection.SessionID)
		return nil, err
	}
	user.LastSignInAt = &now
	return &MagicVerifyResult{
		User: *user, SealedSession: sealed, SessionID: inspection.SessionID, CSRFToken: csrfToken,
	}, nil
}

type Principal struct {
	User                 accounts.User
	SessionID            string
	RotatedSealedSession string
}

// Authenticate verifies the sealed WorkOS cookie, refreshes only when needed,
// then re-checks local revocation and account state on every request.
func (s *AuthService) Authenticate(ctx context.Context, sealedSession string) (*Principal, error) {
	if sealedSession == "" {
		return nil, ErrUnauthenticated
	}
	inspection, err := s.provider.InspectSession(sealedSession, s.cookiePassword)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	rotated := ""
	if !inspection.Authenticated && inspection.NeedsRefresh {
		refresh, refreshErr := s.provider.RefreshSession(ctx, sealedSession, s.cookiePassword)
		if refreshErr != nil || !refresh.Authenticated {
			if refresh.Terminal {
				if inspection.SessionID != "" {
					_ = s.revokeLocally(ctx, inspection.SessionID, "", s.now().UTC().Add(30*24*time.Hour))
				}
				return nil, ErrUnauthenticated
			}
			return nil, ErrSessionUnavailable
		}
		inspection = SessionInspection{
			Authenticated: true, WorkOSUserID: refresh.WorkOSUserID,
			SessionID: refresh.SessionID,
		}
		rotated = refresh.SealedSession
	}
	if !inspection.Authenticated || inspection.WorkOSUserID == "" || inspection.SessionID == "" {
		return nil, ErrUnauthenticated
	}
	revoked, err := s.isLocallyRevoked(ctx, inspection.SessionID)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, ErrUnauthenticated
	}
	user, err := s.accounts.GetUserByWorkOSID(ctx, inspection.WorkOSUserID)
	if err != nil || !user.State.CanAuthenticate() {
		return nil, ErrUnauthenticated
	}
	return &Principal{User: *user, SessionID: inspection.SessionID, RotatedSealedSession: rotated}, nil
}

// Logout records local revocation before attempting WorkOS revocation. The HTTP
// layer should clear its cookie even when the upstream call fails.
func (s *AuthService) Logout(ctx context.Context, sealedSession string) error {
	inspection, err := s.provider.InspectSession(sealedSession, s.cookiePassword)
	if err != nil || inspection.SessionID == "" {
		return ErrUnauthenticated
	}
	userID := ""
	if inspection.WorkOSUserID != "" {
		if user, lookupErr := s.accounts.GetUserByWorkOSID(ctx, inspection.WorkOSUserID); lookupErr == nil {
			userID = user.ID
		}
	}
	if err := s.revokeLocally(ctx, inspection.SessionID, userID, s.now().UTC().Add(30*24*time.Hour)); err != nil {
		return err
	}
	remoteErr := s.provider.RevokeSession(ctx, inspection.SessionID)
	if auditErr := s.record(ctx, optionalID(userID), "authentication.logged_out", "session", inspection.SessionID, nil); auditErr != nil {
		return auditErr
	}
	return remoteErr
}

func (s *AuthService) RevokeSession(ctx context.Context, sessionID, userID string, expiresAt time.Time, actor accounts.MutationContext) error {
	if err := s.authorizeSessionOwner(ctx, userID, actor.ActorID); err != nil {
		return err
	}
	if err := s.revokeLocally(ctx, sessionID, userID, expiresAt); err != nil {
		return err
	}
	remoteErr := s.provider.RevokeSession(ctx, sessionID)
	if auditErr := s.recordWithContext(ctx, optionalID(actor.ActorID), "authentication.session_revoked", "session", sessionID, nil, actor); auditErr != nil {
		return auditErr
	}
	return remoteErr
}

func (s *AuthService) revokeLocally(ctx context.Context, sessionID, userID string, expiresAt time.Time) error {
	if sessionID == "" {
		return ErrUnauthenticated
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO revoked_sessions (session_id, user_id, expires_at, revoked_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(session_id) DO UPDATE SET
			user_id = COALESCE(revoked_sessions.user_id, excluded.user_id),
			expires_at = MAX(revoked_sessions.expires_at, excluded.expires_at)`,
		sessionID, nullIfEmpty(userID), formatTime(expiresAt.UTC()), formatTime(s.now().UTC()))
	if err != nil {
		return fmt.Errorf("auth: persist session revocation: %w", err)
	}
	return nil
}

func (s *AuthService) isLocallyRevoked(ctx context.Context, sessionID string) (bool, error) {
	var exists int
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(SELECT 1 FROM revoked_sessions WHERE session_id = ? AND expires_at > ?)`,
		sessionID, formatTime(s.now().UTC())).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("auth: check session revocation: %w", err)
	}
	return exists != 0, nil
}

func (s *AuthService) recordFailure(ctx context.Context, reason string) {
	_ = s.record(ctx, nil, "authentication.magic_failed", "authentication", "", map[string]any{"reason": reason})
}

func (s *AuthService) record(ctx context.Context, actorID *string, action, targetType, targetID string, metadata map[string]any) error {
	return s.audit.Record(ctx, audit.Event{ActorID: actorID, Action: action, TargetType: targetType, TargetID: targetID, Metadata: metadata})
}

func (s *AuthService) recordWithContext(ctx context.Context, actorID *string, action, targetType, targetID string, metadata map[string]any, mutation accounts.MutationContext) error {
	return s.audit.Record(ctx, audit.Event{
		ActorID: actorID, Action: action, TargetType: targetType, TargetID: targetID,
		Metadata: metadata, IPAddress: mutation.IPAddress, UserAgent: mutation.UserAgent, RequestID: mutation.RequestID,
	})
}

func optionalID(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func (s *AuthService) allowAttempt(ctx context.Context, key string, limit int, window time.Duration) error {
	allowed, retryAfter := s.limiter.Allow(ctx, key, limit, window)
	if allowed {
		return nil
	}
	return &RateLimitError{RetryAfter: retryAfter}
}
