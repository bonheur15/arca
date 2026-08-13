package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (r *Repository) CreateSupportAccess(ctx context.Context, actorID, targetUserID, reason string, expiresAt time.Time) (*SupportAccess, error) {
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) < 10 || len([]rune(reason)) > 500 {
		return nil, fmt.Errorf("%w: support reason must contain 10 to 500 characters", ErrInvalidInput)
	}
	if actorID == targetUserID || !expiresAt.After(r.now()) {
		return nil, fmt.Errorf("%w: invalid support access target or expiration", ErrInvalidInput)
	}
	if _, err := r.GetUserByID(ctx, targetUserID); err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := r.now().UTC()
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO support_access (id, actor_id, target_user_id, reason, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, id, actorID, targetUserID, reason,
		formatTime(expiresAt.UTC()), formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("accounts: create support access: %w", err)
	}
	return &SupportAccess{ID: id, ActorID: actorID, TargetUserID: targetUserID, Reason: reason, ExpiresAt: expiresAt.UTC(), CreatedAt: now}, nil
}

func (r *Repository) GetActiveSupportAccess(ctx context.Context, actorID string) (*SupportAccess, error) {
	access, err := scanSupportAccess(r.db.QueryRowContext(ctx, supportAccessSelect+`
		WHERE actor_id = ? AND revoked_at IS NULL AND expires_at > ?
		ORDER BY expires_at DESC LIMIT 1`, actorID, formatTime(r.now().UTC())))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("accounts: read support access: %w", err)
	}
	return access, nil
}

func (r *Repository) RevokeSupportAccess(ctx context.Context, id string) (*SupportAccess, error) {
	result, err := r.db.ExecContext(ctx, `
		UPDATE support_access SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		formatTime(r.now().UTC()), id)
	if err != nil {
		return nil, fmt.Errorf("accounts: revoke support access: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return nil, ErrNotFound
	}
	access, err := scanSupportAccess(r.db.QueryRowContext(ctx, supportAccessSelect+` WHERE id = ?`, id))
	if err != nil {
		return nil, fmt.Errorf("accounts: read revoked support access: %w", err)
	}
	return access, nil
}

const supportAccessSelect = `SELECT id, actor_id, target_user_id, reason, expires_at, revoked_at, created_at FROM support_access`

func scanSupportAccess(row scanner) (*SupportAccess, error) {
	var access SupportAccess
	var expiresAt, createdAt string
	var revokedAt sql.NullString
	if err := row.Scan(&access.ID, &access.ActorID, &access.TargetUserID, &access.Reason, &expiresAt, &revokedAt, &createdAt); err != nil {
		return nil, err
	}
	var err error
	access.ExpiresAt, err = parseTime(expiresAt)
	if err != nil {
		return nil, err
	}
	access.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return nil, err
	}
	if revokedAt.Valid {
		value, parseErr := parseTime(revokedAt.String)
		if parseErr != nil {
			return nil, parseErr
		}
		access.RevokedAt = &value
	}
	return &access, nil
}

func (s *Service) GrantSupportAccess(ctx context.Context, targetUserID, reason string, mutation MutationContext) (*SupportAccess, error) {
	if err := s.requireSuperadmin(ctx, mutation.ActorID); err != nil {
		return nil, err
	}
	access, err := s.repository.CreateSupportAccess(ctx, mutation.ActorID, targetUserID, reason, s.now().UTC().Add(15*time.Minute))
	if err != nil {
		return nil, err
	}
	if err := s.record(ctx, mutation, "support_access.granted", "support_access", access.ID, map[string]any{"target_user_id": targetUserID, "reason": access.Reason, "expires_at": access.ExpiresAt}); err != nil {
		return access, err
	}
	return access, nil
}

func (s *Service) RevokeSupportAccess(ctx context.Context, accessID string, mutation MutationContext) (*SupportAccess, error) {
	if err := s.requireSuperadmin(ctx, mutation.ActorID); err != nil {
		return nil, err
	}
	access, err := s.repository.RevokeSupportAccess(ctx, accessID)
	if err != nil {
		return nil, err
	}
	if err := s.record(ctx, mutation, "support_access.revoked", "support_access", access.ID, map[string]any{"target_user_id": access.TargetUserID}); err != nil {
		return access, err
	}
	return access, nil
}
