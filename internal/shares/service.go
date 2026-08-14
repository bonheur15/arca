package shares

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound          = errors.New("share not found")
	ErrForbidden         = errors.New("share operation forbidden")
	ErrInvalid           = errors.New("invalid share request")
	ErrCodeUnavailable   = errors.New("unable to allocate a public share code")
	ErrPublicUnavailable = errors.New("public share unavailable")
)

type Permission string

const (
	PermissionNone   Permission = ""
	PermissionViewer Permission = "viewer"
	PermissionEditor Permission = "editor"
)

type Service struct {
	db      *sql.DB
	codeKey []byte
	now     func() time.Time
}

func New(db *sql.DB, codeKey []byte) (*Service, error) {
	if db == nil {
		return nil, errors.New("database is required")
	}
	if len(codeKey) < 32 {
		return nil, errors.New("public-code HMAC key must contain at least 32 bytes")
	}
	return &Service{db: db, codeKey: append([]byte(nil), codeKey...), now: time.Now}, nil
}

type CreateInternalInput struct {
	OwnerID              string
	RootIDs              []string
	RecipientIDs         []string
	Permission           Permission
	ExpiresAt            *time.Time
	AllowEditorUploads   bool
	EditorAllowanceBytes *int64
}

type InternalShare struct {
	ID                   string     `json:"id"`
	OwnerID              string     `json:"owner_id"`
	Permission           Permission `json:"permission"`
	RootIDs              []string   `json:"root_ids"`
	RecipientIDs         []string   `json:"recipient_ids"`
	ExpiresAt            *time.Time `json:"expires_at,omitempty"`
	AllowEditorUploads   bool       `json:"allow_editor_uploads"`
	EditorAllowanceBytes *int64     `json:"editor_allowance_bytes,omitempty"`
	EditorUsedBytes      int64      `json:"editor_used_bytes"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

func (s *Service) CreateInternal(ctx context.Context, input CreateInternalInput) (InternalShare, error) {
	if input.OwnerID == "" || len(input.RootIDs) == 0 || len(input.RootIDs) > 500 || len(input.RecipientIDs) == 0 || len(input.RecipientIDs) > 500 {
		return InternalShare{}, ErrInvalid
	}
	if input.Permission != PermissionViewer && input.Permission != PermissionEditor {
		return InternalShare{}, ErrInvalid
	}
	if input.AllowEditorUploads {
		if input.Permission != PermissionEditor || input.EditorAllowanceBytes == nil || *input.EditorAllowanceBytes <= 0 {
			return InternalShare{}, ErrInvalid
		}
	} else {
		input.EditorAllowanceBytes = nil
	}
	now := s.now().UTC()
	if input.ExpiresAt != nil && !input.ExpiresAt.After(now) {
		return InternalShare{}, ErrInvalid
	}
	var allowed bool
	err := s.db.QueryRowContext(ctx, `SELECT p.allow_internal_sharing FROM users u
		JOIN user_policies p ON p.user_id = u.id
		WHERE u.id = ? AND u.state IN ('active', 'over_quota')`, input.OwnerID).Scan(&allowed)
	if errors.Is(err, sql.ErrNoRows) || !allowed {
		return InternalShare{}, ErrForbidden
	}
	if err != nil {
		return InternalShare{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return InternalShare{}, err
	}
	defer tx.Rollback()
	for _, rootID := range unique(input.RootIDs) {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE id = ? AND owner_id = ? AND trashed_at IS NULL`, rootID, input.OwnerID).Scan(&count); err != nil {
			return InternalShare{}, err
		}
		if count != 1 {
			return InternalShare{}, ErrForbidden
		}
	}
	for _, recipientID := range unique(input.RecipientIDs) {
		if recipientID == input.OwnerID {
			return InternalShare{}, ErrInvalid
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id = ? AND state IN ('active', 'over_quota')`, recipientID).Scan(&count); err != nil {
			return InternalShare{}, err
		}
		if count != 1 {
			return InternalShare{}, ErrInvalid
		}
	}
	id := newID()
	var expires any
	if input.ExpiresAt != nil {
		expires = input.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO shares
        (id, owner_id, permission, allow_editor_uploads, editor_allowance_bytes, editor_used_bytes, expires_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)`, id, input.OwnerID, input.Permission, boolInt(input.AllowEditorUploads), nullableInt(input.EditorAllowanceBytes), expires, stamp(now), stamp(now)); err != nil {
		return InternalShare{}, err
	}
	roots := unique(input.RootIDs)
	for _, rootID := range roots {
		if _, err := tx.ExecContext(ctx, `INSERT INTO share_roots(share_id, node_id) VALUES (?, ?)`, id, rootID); err != nil {
			return InternalShare{}, err
		}
	}
	recipients := unique(input.RecipientIDs)
	for _, recipientID := range recipients {
		if _, err := tx.ExecContext(ctx, `INSERT INTO share_recipients(share_id, user_id) VALUES (?, ?)`, id, recipientID); err != nil {
			return InternalShare{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return InternalShare{}, err
	}
	return InternalShare{
		ID: id, OwnerID: input.OwnerID, Permission: input.Permission, RootIDs: roots,
		RecipientIDs: recipients, ExpiresAt: input.ExpiresAt, AllowEditorUploads: input.AllowEditorUploads,
		EditorAllowanceBytes: input.EditorAllowanceBytes, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (s *Service) RevokeInternal(ctx context.Context, actorID, shareID string, superadmin bool) error {
	now := stamp(s.now().UTC())
	query := `UPDATE shares SET revoked_at = ?, updated_at = ? WHERE id = ? AND revoked_at IS NULL`
	args := []any{now, now, shareID}
	if !superadmin {
		query += ` AND owner_id = ?`
		args = append(args, actorID)
	}
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Service) PermissionForNode(ctx context.Context, userID, nodeID string) (Permission, error) {
	var ownerID string
	var trashed sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT owner_id, trashed_at FROM nodes WHERE id = ?`, nodeID).Scan(&ownerID, &trashed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return PermissionNone, ErrNotFound
		}
		return PermissionNone, err
	}
	if trashed.Valid {
		return PermissionNone, ErrNotFound
	}
	if ownerID == userID {
		return PermissionEditor, nil
	}
	now := stamp(s.now().UTC())
	rows, err := s.db.QueryContext(ctx, `
        WITH RECURSIVE ancestors(id, parent_id, trashed_at) AS (
            SELECT id, parent_id, trashed_at FROM nodes WHERE id = ?
            UNION ALL
            SELECT n.id, n.parent_id, n.trashed_at FROM nodes n JOIN ancestors a ON n.id = a.parent_id
        )
        SELECT sh.permission
        FROM ancestors a
        JOIN share_roots sr ON sr.node_id = a.id
        JOIN shares sh ON sh.id = sr.share_id
        JOIN share_recipients r ON r.share_id = sh.id
        WHERE r.user_id = ? AND sh.revoked_at IS NULL AND (sh.expires_at IS NULL OR sh.expires_at > ?)
          AND NOT EXISTS (SELECT 1 FROM ancestors dirty WHERE dirty.trashed_at IS NOT NULL)
        ORDER BY CASE sh.permission WHEN 'editor' THEN 2 ELSE 1 END DESC
        LIMIT 1`, nodeID, userID, now)
	if err != nil {
		return PermissionNone, err
	}
	defer rows.Close()
	if rows.Next() {
		var permission Permission
		if err := rows.Scan(&permission); err != nil {
			return PermissionNone, err
		}
		return permission, nil
	}
	return PermissionNone, nil
}

type CreatePublicInput struct {
	OwnerID         string
	RootIDs         []string
	TTL             time.Duration
	RedemptionLimit int
}

type PublicShare struct {
	ID              string    `json:"id"`
	Code            string    `json:"code,omitempty"`
	OwnerID         string    `json:"owner_id"`
	RootIDs         []string  `json:"root_ids"`
	ExpiresAt       time.Time `json:"expires_at"`
	RedemptionLimit int       `json:"redemption_limit"`
	RedemptionCount int       `json:"redemption_count"`
	Revoked         bool      `json:"revoked"`
	CreatedAt       time.Time `json:"created_at"`
}

func (s *Service) CreatePublic(ctx context.Context, input CreatePublicInput) (PublicShare, error) {
	if input.OwnerID == "" || len(input.RootIDs) == 0 || len(input.RootIDs) > 500 || input.TTL <= 0 || input.TTL > 30*time.Minute || input.RedemptionLimit < 1 || input.RedemptionLimit > 10 {
		return PublicShare{}, ErrInvalid
	}
	var allow bool
	var maxTTL, maxRedemptions, maxActive int
	err := s.db.QueryRowContext(ctx, `SELECT p.allow_public_sharing, p.max_public_ttl_minutes, p.max_public_redemptions, p.max_active_public_shares
        FROM users u JOIN user_policies p ON p.user_id = u.id WHERE u.id = ? AND u.state IN ('active', 'over_quota')`, input.OwnerID).
		Scan(&allow, &maxTTL, &maxRedemptions, &maxActive)
	if errors.Is(err, sql.ErrNoRows) || !allow {
		return PublicShare{}, ErrForbidden
	}
	if err != nil {
		return PublicShare{}, err
	}
	if input.TTL > time.Duration(maxTTL)*time.Minute || input.RedemptionLimit > maxRedemptions {
		return PublicShare{}, ErrForbidden
	}
	var active int
	now := s.now().UTC()
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM public_shares WHERE owner_id = ? AND revoked_at IS NULL AND expires_at > ?`, input.OwnerID, stamp(now)).Scan(&active); err != nil {
		return PublicShare{}, err
	}
	if active >= maxActive {
		return PublicShare{}, ErrForbidden
	}
	for attempt := 0; attempt < 32; attempt++ {
		code, err := generateCode()
		if err != nil {
			return PublicShare{}, err
		}
		result, err := s.insertPublic(ctx, input, code, now)
		if err == nil {
			return result, nil
		}
		if !isUniqueConstraint(err) {
			return PublicShare{}, err
		}
	}
	return PublicShare{}, ErrCodeUnavailable
}

func (s *Service) insertPublic(ctx context.Context, input CreatePublicInput, code string, now time.Time) (PublicShare, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PublicShare{}, err
	}
	defer tx.Rollback()
	roots := unique(input.RootIDs)
	for _, rootID := range roots {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE id = ? AND owner_id = ? AND trashed_at IS NULL`, rootID, input.OwnerID).Scan(&count); err != nil {
			return PublicShare{}, err
		}
		if count != 1 {
			return PublicShare{}, ErrForbidden
		}
	}
	id := newID()
	expires := now.Add(input.TTL)
	if _, err := tx.ExecContext(ctx, `INSERT INTO public_shares
        (id, owner_id, code_hash, expires_at, redemption_limit, redemption_count, created_at)
        VALUES (?, ?, ?, ?, ?, 0, ?)`, id, input.OwnerID, s.hashCode(code), stamp(expires), input.RedemptionLimit, stamp(now)); err != nil {
		return PublicShare{}, err
	}
	for _, rootID := range roots {
		if _, err := tx.ExecContext(ctx, `INSERT INTO public_share_roots(public_share_id, node_id) VALUES (?, ?)`, id, rootID); err != nil {
			return PublicShare{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return PublicShare{}, err
	}
	return PublicShare{ID: id, Code: code, OwnerID: input.OwnerID, RootIDs: roots, ExpiresAt: expires, RedemptionLimit: input.RedemptionLimit, CreatedAt: now}, nil
}

type PublicSession struct {
	ShareID   string    `json:"share_id"`
	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) Redeem(ctx context.Context, code string) (PublicSession, error) {
	if len(code) != 5 || strings.Trim(code, "0123456789") != "" {
		return PublicSession{}, ErrPublicUnavailable
	}
	now := s.now().UTC()
	var shareID, expiresRaw string
	err := s.db.QueryRowContext(ctx, `UPDATE public_shares
        SET redemption_count = redemption_count + 1
        WHERE code_hash = ? AND revoked_at IS NULL AND expires_at > ? AND redemption_count < redemption_limit
        RETURNING id, expires_at`, s.hashCode(code), stamp(now)).Scan(&shareID, &expiresRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return PublicSession{}, ErrPublicUnavailable
	}
	if err != nil {
		return PublicSession{}, err
	}
	expires, err := parseStamp(expiresRaw)
	if err != nil {
		return PublicSession{}, err
	}
	token, err := randomToken(32)
	if err != nil {
		return PublicSession{}, err
	}
	sessionID := newID()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO public_access_sessions
        (id, public_share_id, token_hash, expires_at, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?)`,
		sessionID, shareID, tokenHash(token), expiresRaw, stamp(now), stamp(now)); err != nil {
		return PublicSession{}, err
	}
	return PublicSession{ShareID: shareID, Token: token, ExpiresAt: expires}, nil
}

func (s *Service) ResolvePublicSession(ctx context.Context, token string) (PublicSession, error) {
	if token == "" {
		return PublicSession{}, ErrPublicUnavailable
	}
	now := s.now().UTC()
	var shareID, expiresRaw string
	err := s.db.QueryRowContext(ctx, `SELECT ps.id, ps.expires_at
        FROM public_access_sessions pas JOIN public_shares ps ON ps.id = pas.public_share_id
        WHERE pas.token_hash = ? AND pas.expires_at > ? AND ps.expires_at > ? AND ps.revoked_at IS NULL`,
		tokenHash(token), stamp(now), stamp(now)).Scan(&shareID, &expiresRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return PublicSession{}, ErrPublicUnavailable
	}
	if err != nil {
		return PublicSession{}, err
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE public_access_sessions SET last_used_at = ? WHERE token_hash = ?`, stamp(now), tokenHash(token))
	expires, err := parseStamp(expiresRaw)
	if err != nil {
		return PublicSession{}, err
	}
	return PublicSession{ShareID: shareID, ExpiresAt: expires}, nil
}

func (s *Service) PublicRoots(ctx context.Context, shareID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id FROM public_share_roots WHERE public_share_id = ? ORDER BY node_id`, shareID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func (s *Service) CanAccessPublicNode(ctx context.Context, shareID, nodeID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
        WITH RECURSIVE ancestors(id, parent_id, trashed_at) AS (
            SELECT id, parent_id, trashed_at FROM nodes WHERE id = ?
            UNION ALL
            SELECT n.id, n.parent_id, n.trashed_at FROM nodes n JOIN ancestors a ON n.id = a.parent_id
        )
        SELECT COUNT(*) FROM ancestors a
        JOIN public_share_roots r ON r.node_id = a.id
        WHERE r.public_share_id = ?
          AND NOT EXISTS (SELECT 1 FROM ancestors dirty WHERE dirty.trashed_at IS NOT NULL)`, nodeID, shareID).Scan(&count)
	return count > 0, err
}

func (s *Service) RevokePublic(ctx context.Context, actorID, shareID string, superadmin bool) error {
	now := stamp(s.now().UTC())
	query := `UPDATE public_shares SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`
	args := []any{now, shareID}
	if !superadmin {
		query += ` AND owner_id = ?`
		args = append(args, actorID)
	}
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Service) hashCode(code string) []byte {
	mac := hmac.New(sha256.New, s.codeKey)
	_, _ = mac.Write([]byte(code))
	return mac.Sum(nil)
}

func generateCode() (string, error) {
	number, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		return "", fmt.Errorf("generate share code: %w", err)
	}
	return fmt.Sprintf("%05d", number.Int64()), nil
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func newID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}

func unique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableInt(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func stamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseStamp(value string) (time.Time, error) { return time.Parse(time.RFC3339Nano, value) }

func isUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}
