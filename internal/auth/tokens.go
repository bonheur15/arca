package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"arca/internal/accounts"
	"arca/internal/audit"

	"github.com/google/uuid"
)

type Scope string

const (
	ScopeFilesRead    Scope = "files:read"
	ScopeFilesWrite   Scope = "files:write"
	ScopeSharesRead   Scope = "shares:read"
	ScopeSharesWrite  Scope = "shares:write"
	ScopeTokensManage Scope = "tokens:manage"
	ScopeAdminAll     Scope = "admin:*"
)

var allowedScopes = map[Scope]struct{}{
	ScopeFilesRead: {}, ScopeFilesWrite: {}, ScopeSharesRead: {},
	ScopeSharesWrite: {}, ScopeTokensManage: {}, ScopeAdminAll: {},
}

type PersonalAccessToken struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []Scope    `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

type CreatedPersonalAccessToken struct {
	PersonalAccessToken
	Token string `json:"token"`
}

type TokenPrincipal struct {
	User   accounts.User
	Token  PersonalAccessToken
	Scopes map[Scope]struct{}
}

func (p *TokenPrincipal) HasScope(scope Scope) bool {
	if p == nil {
		return false
	}
	if _, ok := p.Scopes[ScopeAdminAll]; ok {
		return true
	}
	_, ok := p.Scopes[scope]
	return ok
}

type TokenService struct {
	db       *sql.DB
	accounts *accounts.Repository
	secret   []byte
	audit    audit.Recorder
	now      func() time.Time
}

func NewTokenService(db *sql.DB, repository *accounts.Repository, secret []byte, recorder audit.Recorder) (*TokenService, error) {
	if db == nil || repository == nil {
		return nil, errors.New("auth: token database and account repository are required")
	}
	if len(secret) < 32 {
		return nil, errors.New("auth: personal access token secret must contain at least 32 bytes")
	}
	if recorder == nil {
		recorder = audit.NopRecorder{}
	}
	return &TokenService{db: db, accounts: repository, secret: append([]byte(nil), secret...), audit: recorder, now: time.Now}, nil
}

func (s *TokenService) Create(ctx context.Context, userID, name string, scopes []Scope, expiresAt *time.Time, mutation accounts.MutationContext) (*CreatedPersonalAccessToken, error) {
	if err := s.authorizeOwnerOrAdmin(ctx, userID, mutation.ActorID); err != nil {
		return nil, err
	}
	user, err := s.accounts.GetUserByID(ctx, userID)
	if err != nil || !user.State.CanAuthenticate() {
		return nil, ErrForbidden
	}
	policy, err := s.accounts.GetPolicy(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !policy.AllowAPITokens {
		return nil, ErrTokenPolicy
	}
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 100 {
		return nil, fmt.Errorf("auth: token name must contain 1 to 100 characters")
	}
	normalizedScopes, err := validateScopes(scopes, user.Role)
	if err != nil {
		return nil, err
	}
	if expiresAt != nil && !expiresAt.After(s.now()) {
		return nil, fmt.Errorf("auth: token expiration must be in the future")
	}
	plain, prefix, hash, err := s.generateToken()
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("auth: generate token id: %w", err)
	}
	now := s.now().UTC()
	encodedScopes, _ := json.Marshal(normalizedScopes)
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO api_tokens (id, user_id, name, token_prefix, token_hash, scopes, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id.String(), userID, name, prefix, hash,
		string(encodedScopes), nullableTime(expiresAt), formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("auth: persist personal access token: %w", err)
	}
	token := PersonalAccessToken{
		ID: id.String(), UserID: userID, Name: name, Prefix: prefix,
		Scopes: normalizedScopes, ExpiresAt: expiresAt, CreatedAt: now,
	}
	if err := s.record(ctx, mutation, "api_token.created", token.ID, map[string]any{"scopes": normalizedScopes}); err != nil {
		return nil, err
	}
	return &CreatedPersonalAccessToken{PersonalAccessToken: token, Token: plain}, nil
}

func (s *TokenService) Authenticate(ctx context.Context, plaintext string) (*TokenPrincipal, error) {
	prefix, ok := tokenPrefix(plaintext)
	if !ok {
		return nil, ErrInvalidToken
	}
	var token PersonalAccessToken
	var storedHash []byte
	var encodedScopes, created string
	var expires, lastUsed, revoked sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, name, token_prefix, token_hash, scopes,
			expires_at, last_used_at, revoked_at, created_at
		FROM api_tokens WHERE token_prefix = ?`, prefix).Scan(
		&token.ID, &token.UserID, &token.Name, &token.Prefix, &storedHash,
		&encodedScopes, &expires, &lastUsed, &revoked, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, fmt.Errorf("auth: read personal access token: %w", err)
	}
	if !hmac.Equal(storedHash, s.hashToken(plaintext)) || revoked.Valid {
		return nil, ErrInvalidToken
	}
	if err := json.Unmarshal([]byte(encodedScopes), &token.Scopes); err != nil {
		return nil, fmt.Errorf("auth: decode token scopes: %w", err)
	}
	token.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	if expires.Valid {
		value, parseErr := parseTime(expires.String)
		if parseErr != nil {
			return nil, parseErr
		}
		token.ExpiresAt = &value
		if !value.After(s.now()) {
			return nil, ErrInvalidToken
		}
	}
	if lastUsed.Valid {
		value, parseErr := parseTime(lastUsed.String)
		if parseErr != nil {
			return nil, parseErr
		}
		token.LastUsedAt = &value
	}
	user, err := s.accounts.GetUserByID(ctx, token.UserID)
	if err != nil || !user.State.CanAuthenticate() {
		return nil, ErrInvalidToken
	}
	policy, err := s.accounts.GetPolicy(ctx, user.ID)
	if err != nil || !policy.AllowAPITokens {
		return nil, ErrInvalidToken
	}
	now := s.now().UTC()
	_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, formatTime(now), token.ID)
	token.LastUsedAt = &now
	scopeSet := make(map[Scope]struct{}, len(token.Scopes))
	for _, scope := range token.Scopes {
		scopeSet[scope] = struct{}{}
	}
	return &TokenPrincipal{User: *user, Token: token, Scopes: scopeSet}, nil
}

func (s *TokenService) List(ctx context.Context, userID, actorID string) ([]PersonalAccessToken, error) {
	if err := s.authorizeOwnerOrAdmin(ctx, userID, actorID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, name, token_prefix, scopes, expires_at, last_used_at, revoked_at, created_at
		FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, fmt.Errorf("auth: list personal access tokens: %w", err)
	}
	defer rows.Close()
	var tokens []PersonalAccessToken
	for rows.Next() {
		var token PersonalAccessToken
		var scopes, created string
		var expires, lastUsed, revoked sql.NullString
		if err := rows.Scan(&token.ID, &token.UserID, &token.Name, &token.Prefix, &scopes, &expires, &lastUsed, &revoked, &created); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(scopes), &token.Scopes); err != nil {
			return nil, err
		}
		token.CreatedAt, _ = parseTime(created)
		token.ExpiresAt = parseNullableTime(expires)
		token.LastUsedAt = parseNullableTime(lastUsed)
		token.RevokedAt = parseNullableTime(revoked)
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (s *TokenService) Revoke(ctx context.Context, tokenID, userID string, mutation accounts.MutationContext) error {
	if err := s.authorizeOwnerOrAdmin(ctx, userID, mutation.ActorID); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
		formatTime(s.now().UTC()), tokenID, userID)
	if err != nil {
		return fmt.Errorf("auth: revoke personal access token: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return ErrInvalidToken
	}
	return s.record(ctx, mutation, "api_token.revoked", tokenID, nil)
}

func (s *TokenService) authorizeOwnerOrAdmin(ctx context.Context, userID, actorID string) error {
	if actorID == "" {
		return ErrForbidden
	}
	if userID == actorID {
		return nil
	}
	actor, err := s.accounts.GetUserByID(ctx, actorID)
	if err != nil || actor.Role != accounts.RoleSuperadmin || !actor.State.CanAuthenticate() {
		return ErrForbidden
	}
	return nil
}

func (s *TokenService) generateToken() (plaintext, prefix string, hash []byte, err error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", "", nil, fmt.Errorf("auth: generate personal access token: %w", err)
	}
	plaintext = "arca_pat_" + base64.RawURLEncoding.EncodeToString(random)
	prefix, _ = tokenPrefix(plaintext)
	return plaintext, prefix, s.hashToken(plaintext), nil
}

func (s *TokenService) hashToken(plaintext string) []byte {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte("arca:personal-access-token:v1\x00"))
	_, _ = mac.Write([]byte(plaintext))
	return mac.Sum(nil)
}

func tokenPrefix(plaintext string) (string, bool) {
	if !strings.HasPrefix(plaintext, "arca_pat_") || len(plaintext) < len("arca_pat_")+12 {
		return "", false
	}
	return plaintext[:len("arca_pat_")+12], true
}

func validateScopes(scopes []Scope, role accounts.Role) ([]Scope, error) {
	if len(scopes) == 0 {
		return nil, fmt.Errorf("auth: at least one scope is required")
	}
	seen := make(map[Scope]struct{}, len(scopes))
	normalized := make([]Scope, 0, len(scopes))
	for _, scope := range scopes {
		if _, ok := allowedScopes[scope]; !ok {
			return nil, fmt.Errorf("auth: unsupported token scope %q", scope)
		}
		if scope == ScopeAdminAll && role != accounts.RoleSuperadmin {
			return nil, ErrForbidden
		}
		if _, duplicate := seen[scope]; duplicate {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	return normalized, nil
}

func (s *TokenService) record(ctx context.Context, mutation accounts.MutationContext, action, tokenID string, metadata map[string]any) error {
	actor := mutation.ActorID
	return s.audit.Record(ctx, audit.Event{
		ActorID: &actor, Action: action, TargetType: "api_token", TargetID: tokenID,
		Metadata: metadata, IPAddress: mutation.IPAddress, UserAgent: mutation.UserAgent, RequestID: mutation.RequestID,
	})
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return formatTime(value.UTC())
}

func parseNullableTime(value sql.NullString) *time.Time {
	if !value.Valid {
		return nil
	}
	parsed, err := parseTime(value.String)
	if err != nil {
		return nil
	}
	return &parsed
}
