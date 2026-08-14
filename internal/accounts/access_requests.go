package accounts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type CreateAccessRequestParams struct {
	Username        string
	Email           string
	DisplayName     string
	Reason          string
	RequesterIPHash []byte
}

func (r *Repository) CreateAccessRequest(ctx context.Context, params CreateAccessRequestParams, statusTokenHash []byte) (*AccessRequest, error) {
	username, usernameKey, err := NormalizeUsername(params.Username)
	if err != nil {
		return nil, err
	}
	email, emailKey, err := NormalizeEmail(params.Email)
	if err != nil {
		return nil, err
	}
	displayName, err := NormalizeDisplayName(params.DisplayName)
	if err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(params.Reason)
	if len([]rune(reason)) > 500 {
		return nil, fmt.Errorf("%w: request reason is too long", ErrInvalidInput)
	}
	if len(statusTokenHash) == 0 {
		return nil, fmt.Errorf("%w: status token hash is required", ErrInvalidInput)
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	now := r.now().UTC()
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO access_requests (
			id, username, username_key, email, email_key, display_name,
			reason, state, status_token_hash, requester_ip_hash, requested_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`,
		id, username, usernameKey, email, emailKey, nullIfEmpty(displayName),
		nullIfEmpty(reason), statusTokenHash, nullableBytes(params.RequesterIPHash), formatTime(now),
	)
	if err != nil {
		return nil, classifyWriteError("create access request", err)
	}
	return &AccessRequest{
		ID: id, Username: username, UsernameKey: usernameKey, Email: email,
		EmailKey: emailKey, DisplayName: displayName, Reason: reason,
		State: AccessRequestPending, RequestedAt: now,
	}, nil
}

func (r *Repository) GetAccessRequest(ctx context.Context, id string) (*AccessRequest, error) {
	request, err := scanAccessRequest(r.db.QueryRowContext(ctx, accessRequestSelect+` WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("accounts: read access request: %w", err)
	}
	return request, nil
}

func (r *Repository) GetAccessRequestByStatusToken(ctx context.Context, hash []byte) (*AccessRequest, error) {
	request, err := scanAccessRequest(r.db.QueryRowContext(ctx, accessRequestSelect+` WHERE status_token_hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidStatusToken
	}
	if err != nil {
		return nil, fmt.Errorf("accounts: read request status: %w", err)
	}
	return request, nil
}

func (r *Repository) ListAccessRequests(ctx context.Context, state AccessRequestState, limit int, afterID string) ([]AccessRequest, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := r.db.QueryContext(ctx, accessRequestSelect+`
		WHERE (? = '' OR state = ?) AND (? = '' OR id > ?)
		ORDER BY id LIMIT ?`, state, state, afterID, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("accounts: list access requests: %w", err)
	}
	defer rows.Close()
	requests := make([]AccessRequest, 0, limit)
	for rows.Next() {
		request, err := scanAccessRequest(rows)
		if err != nil {
			return nil, fmt.Errorf("accounts: scan access requests: %w", err)
		}
		requests = append(requests, *request)
	}
	return requests, rows.Err()
}

type ReserveApprovalParams struct {
	RequestID      string
	Username       string
	DisplayName    string
	QuotaBytes     int64
	QuotaUnlimited bool
	Policy         Policy
}

// ReserveAccessRequestApproval creates a stable provisioning user and links it
// to the still-pending request. It is idempotent so an upstream identity call
// can be retried safely after a crash.
func (r *Repository) ReserveAccessRequestApproval(ctx context.Context, params ReserveApprovalParams) (*User, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("accounts: begin approval: %w", err)
	}
	defer tx.Rollback()
	request, err := scanAccessRequest(tx.QueryRowContext(ctx, accessRequestSelect+` WHERE id = ?`, params.RequestID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("accounts: read approval request: %w", err)
	}
	if request.State != AccessRequestPending {
		return nil, ErrRequestDecided
	}
	if request.ApprovedUserID != "" {
		user, err := scanUser(tx.QueryRowContext(ctx, userSelect+` WHERE id = ?`, request.ApprovedUserID))
		if err != nil {
			return nil, fmt.Errorf("accounts: read reserved user: %w", err)
		}
		return user, nil
	}
	username := params.Username
	if strings.TrimSpace(username) == "" {
		username = request.Username
	}
	displayName := params.DisplayName
	if strings.TrimSpace(displayName) == "" {
		displayName = request.DisplayName
	}
	user, err := r.createUserTx(ctx, tx, CreateUserParams{
		Username: username, Email: request.Email, DisplayName: displayName,
		Role: RoleMember, State: StateProvisioning, QuotaBytes: params.QuotaBytes,
		QuotaUnlimited: params.QuotaUnlimited, Policy: params.Policy,
	})
	if err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE access_requests SET approved_user_id = ?
		WHERE id = ? AND state = 'pending' AND approved_user_id IS NULL`, user.ID, params.RequestID)
	if err != nil {
		return nil, fmt.Errorf("accounts: reserve approval: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return nil, ErrRequestDecided
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("accounts: commit approval reservation: %w", err)
	}
	return user, nil
}

func (r *Repository) FinalizeAccessRequestApproval(ctx context.Context, requestID, userID, actorID, note string) (*AccessRequest, error) {
	now := r.now().UTC()
	result, err := r.db.ExecContext(ctx, `
		UPDATE access_requests SET state = 'approved', decided_at = ?, decided_by = ?, decision_note = ?
		WHERE id = ? AND state = 'pending' AND approved_user_id = ?
		  AND EXISTS (SELECT 1 FROM users WHERE id = ? AND state = 'active')`,
		formatTime(now), actorID, nullIfEmpty(strings.TrimSpace(note)), requestID, userID, userID)
	if err != nil {
		return nil, fmt.Errorf("accounts: finalize approval: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		request, getErr := r.GetAccessRequest(ctx, requestID)
		if getErr != nil {
			return nil, getErr
		}
		if request.State == AccessRequestApproved && request.ApprovedUserID == userID {
			return request, nil
		}
		return nil, ErrRequestDecided
	}
	return r.GetAccessRequest(ctx, requestID)
}

func (r *Repository) RejectAccessRequest(ctx context.Context, requestID, actorID, note string) (*AccessRequest, error) {
	now := r.now().UTC()
	result, err := r.db.ExecContext(ctx, `
		UPDATE access_requests SET state = 'rejected', decided_at = ?, decided_by = ?, decision_note = ?
		WHERE id = ? AND state = 'pending' AND approved_user_id IS NULL`,
		formatTime(now), actorID, nullIfEmpty(strings.TrimSpace(note)), requestID)
	if err != nil {
		return nil, fmt.Errorf("accounts: reject access request: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		request, getErr := r.GetAccessRequest(ctx, requestID)
		if getErr != nil {
			return nil, getErr
		}
		if request.State != AccessRequestPending || request.ApprovedUserID != "" {
			return nil, ErrRequestDecided
		}
		return nil, ErrInvalidTransition
	}
	return r.GetAccessRequest(ctx, requestID)
}

const accessRequestSelect = `SELECT
	id, username, username_key, email, email_key, COALESCE(display_name, ''),
	COALESCE(reason, ''), state, requested_at, decided_at, COALESCE(decided_by, ''),
	COALESCE(decision_note, ''), COALESCE(approved_user_id, '')
	FROM access_requests`

func scanAccessRequest(row scanner) (*AccessRequest, error) {
	var request AccessRequest
	var state, requested string
	var decided sql.NullString
	err := row.Scan(
		&request.ID, &request.Username, &request.UsernameKey, &request.Email,
		&request.EmailKey, &request.DisplayName, &request.Reason, &state,
		&requested, &decided, &request.DecidedBy, &request.DecisionNote,
		&request.ApprovedUserID,
	)
	if err != nil {
		return nil, err
	}
	request.State = AccessRequestState(state)
	request.RequestedAt, err = parseTime(requested)
	if err != nil {
		return nil, err
	}
	if decided.Valid {
		value, parseErr := parseTime(decided.String)
		if parseErr != nil {
			return nil, parseErr
		}
		request.DecidedAt = &value
	}
	return &request, nil
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

// Rejected access requests are retained for abuse review for thirty days.
func (r *Repository) PurgeRejectedAccessRequests(ctx context.Context, before time.Time) (int64, error) {
	result, err := r.db.ExecContext(ctx, `
		DELETE FROM access_requests WHERE state = 'rejected' AND decided_at < ?`, formatTime(before.UTC()))
	if err != nil {
		return 0, fmt.Errorf("accounts: purge rejected requests: %w", err)
	}
	return result.RowsAffected()
}
