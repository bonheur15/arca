package accounts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Repository struct {
	db  *sql.DB
	now func() time.Time
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db, now: time.Now}
}

type CreateUserParams struct {
	Username       string
	Email          string
	DisplayName    string
	Role           Role
	State          State
	QuotaBytes     int64
	QuotaUnlimited bool
	Policy         Policy
}

func (r *Repository) CreateUser(ctx context.Context, params CreateUserParams) (*User, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("accounts: database is required")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("accounts: begin create user: %w", err)
	}
	defer tx.Rollback()
	user, err := r.createUserTx(ctx, tx, params)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("accounts: commit create user: %w", err)
	}
	return user, nil
}

func (r *Repository) createUserTx(ctx context.Context, tx *sql.Tx, params CreateUserParams) (*User, error) {
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
	if !params.Role.Valid() || !params.State.Valid() {
		return nil, fmt.Errorf("%w: invalid role or state", ErrInvalidInput)
	}
	if params.QuotaBytes < 0 {
		return nil, fmt.Errorf("%w: quota must not be negative", ErrInvalidInput)
	}
	policy := params.Policy
	if policy.MaxItems == 0 {
		policy = DefaultPolicy()
	}
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}
	now := r.now().UTC()
	userID, err := newID()
	if err != nil {
		return nil, err
	}
	rootID, err := newID()
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO users (
			id, username, username_key, email, email_key, display_name,
			role, state, quota_bytes, quota_unlimited, root_node_id,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
		userID, username, usernameKey, email, emailKey, nullIfEmpty(displayName),
		params.Role, params.State, params.QuotaBytes, boolInt(params.QuotaUnlimited),
		formatTime(now), formatTime(now),
	)
	if err != nil {
		return nil, classifyWriteError("create user", err)
	}
	if err := insertPolicy(ctx, tx, userID, policy, now); err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO nodes (
			id, owner_id, parent_id, kind, name, name_key, size_bytes,
			revision, created_by, created_at, updated_at
		) VALUES (?, ?, NULL, 'folder', '', '', 0, 1, ?, ?, ?)`,
		rootID, userID, userID, formatTime(now), formatTime(now),
	)
	if err != nil {
		return nil, fmt.Errorf("accounts: create user root: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET root_node_id = ? WHERE id = ?`, rootID, userID); err != nil {
		return nil, fmt.Errorf("accounts: link user root: %w", err)
	}
	return &User{
		ID: userID, Username: username, UsernameKey: usernameKey,
		Email: email, EmailKey: emailKey, DisplayName: displayName,
		Role: params.Role, State: params.State, QuotaBytes: params.QuotaBytes,
		QuotaUnlimited: params.QuotaUnlimited, RootNodeID: rootID,
		Preferences: DefaultPreferences(), CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (r *Repository) CompleteProvisioning(ctx context.Context, userID, workosUserID string) (*User, error) {
	if workosUserID == "" {
		return nil, fmt.Errorf("%w: WorkOS user id is required", ErrInvalidInput)
	}
	now := r.now().UTC()
	result, err := r.db.ExecContext(ctx, `
		UPDATE users SET workos_user_id = ?, state = 'active', updated_at = ?
		WHERE id = ? AND state = 'provisioning'
		  AND (workos_user_id IS NULL OR workos_user_id = ?)`,
		workosUserID, formatTime(now), userID, workosUserID,
	)
	if err != nil {
		return nil, classifyWriteError("complete provisioning", err)
	}
	changed, _ := result.RowsAffected()
	user, getErr := r.GetUserByID(ctx, userID)
	if getErr != nil {
		return nil, getErr
	}
	if changed == 0 && (user.WorkOSUserID != workosUserID || user.State != StateActive) {
		return nil, ErrInvalidTransition
	}
	return user, nil
}

func (r *Repository) GetUserByID(ctx context.Context, id string) (*User, error) {
	return r.getUser(ctx, `WHERE id = ?`, id)
}

func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	_, key, err := NormalizeEmail(email)
	if err != nil {
		return nil, err
	}
	return r.getUser(ctx, `WHERE email_key = ?`, key)
}

func (r *Repository) GetUserByWorkOSID(ctx context.Context, workosUserID string) (*User, error) {
	if workosUserID == "" {
		return nil, ErrNotFound
	}
	return r.getUser(ctx, `WHERE workos_user_id = ?`, workosUserID)
}

func (r *Repository) GetUserByUsernameOrEmail(ctx context.Context, value string) (*User, error) {
	if strings.Contains(value, "@") {
		return r.GetUserByEmail(ctx, value)
	}
	_, key, err := NormalizeUsername(value)
	if err != nil {
		return nil, err
	}
	return r.getUser(ctx, `WHERE username_key = ?`, key)
}

func (r *Repository) getUser(ctx context.Context, where string, arg any) (*User, error) {
	row := r.db.QueryRowContext(ctx, userSelect+" "+where, arg)
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("accounts: read user: %w", err)
	}
	return user, nil
}

func (r *Repository) ListUsers(ctx context.Context, limit int, afterID string) ([]User, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := r.db.QueryContext(ctx, userSelect+`
		WHERE (? = '' OR id > ?) ORDER BY id LIMIT ?`, afterID, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("accounts: list users: %w", err)
	}
	defer rows.Close()
	users := make([]User, 0, limit)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("accounts: scan users: %w", err)
		}
		users = append(users, *user)
	}
	return users, rows.Err()
}

func (r *Repository) CountUsers(ctx context.Context) (int64, error) {
	var count int64
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE state <> 'deleted'`).Scan(&count); err != nil {
		return 0, fmt.Errorf("accounts: count users: %w", err)
	}
	return count, nil
}

func (r *Repository) GetPolicy(ctx context.Context, userID string) (Policy, error) {
	var policy Policy
	var maxFile, uploadRate, downloadRate sql.NullInt64
	var internal, public, apiTokens int
	var allowedJSON, blockedJSON, updated string
	err := r.db.QueryRowContext(ctx, `
		SELECT max_file_bytes, max_items, allow_internal_sharing,
			allow_public_sharing, allow_api_tokens, max_concurrent_uploads,
			max_pending_uploads, max_active_public_shares,
			max_public_ttl_minutes, max_public_redemptions,
			allowed_mime_groups, blocked_extensions, upload_rate_bytes,
			download_rate_bytes, updated_at
		FROM user_policies WHERE user_id = ?`, userID).Scan(
		&maxFile, &policy.MaxItems, &internal, &public, &apiTokens,
		&policy.MaxConcurrentUploads, &policy.MaxPendingUploads,
		&policy.MaxActivePublicShares, &policy.MaxPublicTTLMinutes,
		&policy.MaxPublicRedemptions, &allowedJSON, &blockedJSON,
		&uploadRate, &downloadRate, &updated,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("accounts: read policy: %w", err)
	}
	policy.AllowInternalSharing = internal != 0
	policy.AllowPublicSharing = public != 0
	policy.AllowAPITokens = apiTokens != 0
	if maxFile.Valid {
		value := maxFile.Int64
		policy.MaxFileBytes = &value
	}
	if uploadRate.Valid {
		value := uploadRate.Int64
		policy.UploadRateBytes = &value
	}
	if downloadRate.Valid {
		value := downloadRate.Int64
		policy.DownloadRateBytes = &value
	}
	if err := json.Unmarshal([]byte(allowedJSON), &policy.AllowedMIMEGroups); err != nil {
		return Policy{}, fmt.Errorf("accounts: decode allowed MIME groups: %w", err)
	}
	if err := json.Unmarshal([]byte(blockedJSON), &policy.BlockedExtensions); err != nil {
		return Policy{}, fmt.Errorf("accounts: decode blocked extensions: %w", err)
	}
	policy.UpdatedAt, err = parseTime(updated)
	return policy, err
}

func (r *Repository) UpdatePreferences(ctx context.Context, userID string, preferences Preferences) (*User, error) {
	if err := ValidatePreferences(preferences); err != nil {
		return nil, err
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE users SET theme_mode = ?, accent = ?, density = ?, reduced_motion = ?, updated_at = ?
		WHERE id = ? AND state <> 'deleted'`, preferences.ThemeMode, preferences.Accent,
		preferences.Density, boolInt(preferences.ReducedMotion), formatTime(r.now().UTC()), userID)
	if err != nil {
		return nil, fmt.Errorf("accounts: update preferences: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return nil, ErrNotFound
	}
	return r.GetUserByID(ctx, userID)
}

func (r *Repository) UpdatePolicyAndQuota(ctx context.Context, userID string, quotaBytes int64, quotaUnlimited bool, policy Policy) (*User, error) {
	if quotaBytes < 0 {
		return nil, fmt.Errorf("%w: quota must not be negative", ErrInvalidInput)
	}
	if err := ValidatePolicy(policy); err != nil {
		return nil, err
	}
	now := r.now().UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("accounts: begin policy update: %w", err)
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE users SET quota_bytes = ?, quota_unlimited = ?,
			state = CASE
				WHEN state = 'active' AND ? = 0 AND used_bytes + reserved_bytes > ? THEN 'over_quota'
				WHEN state = 'over_quota' AND (? = 1 OR used_bytes + reserved_bytes <= ?) THEN 'active'
				ELSE state END,
			updated_at = ?
		WHERE id = ? AND state <> 'deleted'`, quotaBytes, boolInt(quotaUnlimited),
		boolInt(quotaUnlimited), quotaBytes, boolInt(quotaUnlimited), quotaBytes,
		formatTime(now), userID)
	if err != nil {
		return nil, fmt.Errorf("accounts: update quota: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return nil, ErrNotFound
	}
	if err := updatePolicyTx(ctx, tx, userID, policy, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("accounts: commit policy update: %w", err)
	}
	return r.GetUserByID(ctx, userID)
}

func (r *Repository) SetRole(ctx context.Context, userID string, role Role) (*User, error) {
	if !role.Valid() {
		return nil, fmt.Errorf("%w: invalid role", ErrInvalidInput)
	}
	now := formatTime(r.now().UTC())
	var result sql.Result
	var err error
	if role == RoleMember {
		result, err = r.db.ExecContext(ctx, `
			UPDATE users SET role = 'member', updated_at = ?
			WHERE id = ? AND state <> 'deleted'
			  AND (role <> 'superadmin' OR state NOT IN ('active', 'over_quota') OR EXISTS (
				SELECT 1 FROM users other WHERE other.id <> users.id
				  AND other.role = 'superadmin' AND other.state IN ('active', 'over_quota')
			  ))`, now, userID)
	} else {
		result, err = r.db.ExecContext(ctx, `
			UPDATE users SET role = 'superadmin', updated_at = ?
			WHERE id = ? AND state <> 'deleted'`, now, userID)
	}
	if err != nil {
		return nil, fmt.Errorf("accounts: update role: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		user, getErr := r.GetUserByID(ctx, userID)
		if getErr != nil {
			return nil, getErr
		}
		if user.Role == RoleSuperadmin && role == RoleMember && user.State.CanAuthenticate() {
			return nil, ErrLastSuperadmin
		}
		return nil, ErrInvalidTransition
	}
	return r.GetUserByID(ctx, userID)
}

func (r *Repository) SetState(ctx context.Context, userID string, state State, deletionDueAt *time.Time) (*User, error) {
	if !state.Valid() || state == StateProvisioning || state == StateOverQuota {
		return nil, fmt.Errorf("%w: state cannot be set directly", ErrInvalidInput)
	}
	if state == StateDeletionPending && deletionDueAt == nil {
		value := r.now().UTC().Add(7 * 24 * time.Hour)
		deletionDueAt = &value
	}
	now := formatTime(r.now().UTC())
	var due any
	if deletionDueAt != nil {
		due = formatTime(deletionDueAt.UTC())
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE users SET state = ?, deletion_due_at = ?, updated_at = ?
		WHERE id = ? AND state <> 'deleted'
		  AND NOT (
			role = 'superadmin' AND state IN ('active', 'over_quota')
			AND ? IN ('suspended', 'deletion_pending', 'deleted')
			AND NOT EXISTS (
				SELECT 1 FROM users other WHERE other.id <> users.id
				AND other.role = 'superadmin' AND other.state IN ('active', 'over_quota')
			)
		  )`, state, due, now, userID, state)
	if err != nil {
		return nil, fmt.Errorf("accounts: update state: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		user, getErr := r.GetUserByID(ctx, userID)
		if getErr != nil {
			return nil, getErr
		}
		if user.Role == RoleSuperadmin && user.State.CanAuthenticate() {
			return nil, ErrLastSuperadmin
		}
		return nil, ErrInvalidTransition
	}
	return r.GetUserByID(ctx, userID)
}

// RestoreUser returns a suspended or deletion-pending account to active use,
// choosing over_quota when its durable plus reserved bytes exceed its quota.
func (r *Repository) RestoreUser(ctx context.Context, userID string) (*User, error) {
	result, err := r.db.ExecContext(ctx, `
		UPDATE users SET
			state = CASE WHEN quota_unlimited = 0 AND used_bytes + reserved_bytes > quota_bytes
				THEN 'over_quota' ELSE 'active' END,
			deletion_due_at = NULL, updated_at = ?
		WHERE id = ? AND state IN ('suspended', 'deletion_pending')`,
		formatTime(r.now().UTC()), userID)
	if err != nil {
		return nil, fmt.Errorf("accounts: restore user: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return nil, ErrInvalidTransition
	}
	return r.GetUserByID(ctx, userID)
}

func (r *Repository) UpdateLastSignIn(ctx context.Context, userID string, at time.Time) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE users SET last_sign_in_at = ?, updated_at = ?
		WHERE id = ? AND state IN ('active', 'over_quota')`, formatTime(at.UTC()), formatTime(at.UTC()), userID)
	if err != nil {
		return fmt.Errorf("accounts: update last sign in: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return ErrForbidden
	}
	return nil
}

func insertPolicy(ctx context.Context, tx *sql.Tx, userID string, policy Policy, now time.Time) error {
	allowed, err := json.Marshal(policy.AllowedMIMEGroups)
	if err != nil {
		return fmt.Errorf("accounts: encode allowed MIME groups: %w", err)
	}
	blocked, err := json.Marshal(policy.BlockedExtensions)
	if err != nil {
		return fmt.Errorf("accounts: encode blocked extensions: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO user_policies (
			user_id, max_file_bytes, max_items, allow_internal_sharing,
			allow_public_sharing, allow_api_tokens, max_concurrent_uploads,
			max_pending_uploads, max_active_public_shares, max_public_ttl_minutes,
			max_public_redemptions, allowed_mime_groups, blocked_extensions,
			upload_rate_bytes, download_rate_bytes, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, nullableInt64(policy.MaxFileBytes), policy.MaxItems,
		boolInt(policy.AllowInternalSharing), boolInt(policy.AllowPublicSharing), boolInt(policy.AllowAPITokens),
		policy.MaxConcurrentUploads, policy.MaxPendingUploads, policy.MaxActivePublicShares,
		policy.MaxPublicTTLMinutes, policy.MaxPublicRedemptions, string(allowed), string(blocked),
		nullableInt64(policy.UploadRateBytes), nullableInt64(policy.DownloadRateBytes), formatTime(now),
	)
	if err != nil {
		return fmt.Errorf("accounts: create policy: %w", err)
	}
	return nil
}

func updatePolicyTx(ctx context.Context, tx *sql.Tx, userID string, policy Policy, now time.Time) error {
	allowed, _ := json.Marshal(policy.AllowedMIMEGroups)
	blocked, _ := json.Marshal(policy.BlockedExtensions)
	_, err := tx.ExecContext(ctx, `
		UPDATE user_policies SET max_file_bytes = ?, max_items = ?,
			allow_internal_sharing = ?, allow_public_sharing = ?, allow_api_tokens = ?,
			max_concurrent_uploads = ?, max_pending_uploads = ?,
			max_active_public_shares = ?, max_public_ttl_minutes = ?,
			max_public_redemptions = ?, allowed_mime_groups = ?, blocked_extensions = ?,
			upload_rate_bytes = ?, download_rate_bytes = ?, updated_at = ?
		WHERE user_id = ?`, nullableInt64(policy.MaxFileBytes), policy.MaxItems,
		boolInt(policy.AllowInternalSharing), boolInt(policy.AllowPublicSharing), boolInt(policy.AllowAPITokens),
		policy.MaxConcurrentUploads, policy.MaxPendingUploads, policy.MaxActivePublicShares,
		policy.MaxPublicTTLMinutes, policy.MaxPublicRedemptions, string(allowed), string(blocked),
		nullableInt64(policy.UploadRateBytes), nullableInt64(policy.DownloadRateBytes), formatTime(now), userID)
	if err != nil {
		return fmt.Errorf("accounts: update policy: %w", err)
	}
	return nil
}

const userSelect = `SELECT
	id, COALESCE(workos_user_id, ''), username, username_key, email, email_key,
	COALESCE(display_name, ''), role, state, quota_bytes, quota_unlimited,
	used_bytes, reserved_bytes, COALESCE(root_node_id, ''), theme_mode, accent,
	density, reduced_motion, last_sign_in_at, deletion_due_at, created_at, updated_at
	FROM users`

type scanner interface{ Scan(...any) error }

func scanUser(row scanner) (*User, error) {
	var user User
	var role, state, theme, density string
	var unlimited, reduced int
	var lastSignIn, deletionDue sql.NullString
	var created, updated string
	err := row.Scan(
		&user.ID, &user.WorkOSUserID, &user.Username, &user.UsernameKey,
		&user.Email, &user.EmailKey, &user.DisplayName, &role, &state,
		&user.QuotaBytes, &unlimited, &user.UsedBytes, &user.ReservedBytes,
		&user.RootNodeID, &theme, &user.Preferences.Accent, &density, &reduced,
		&lastSignIn, &deletionDue, &created, &updated,
	)
	if err != nil {
		return nil, err
	}
	user.Role = Role(role)
	user.State = State(state)
	user.QuotaUnlimited = unlimited != 0
	user.Preferences.ThemeMode = ThemeMode(theme)
	user.Preferences.Density = Density(density)
	user.Preferences.ReducedMotion = reduced != 0
	if user.CreatedAt, err = parseTime(created); err != nil {
		return nil, err
	}
	if user.UpdatedAt, err = parseTime(updated); err != nil {
		return nil, err
	}
	if lastSignIn.Valid {
		value, parseErr := parseTime(lastSignIn.String)
		if parseErr != nil {
			return nil, parseErr
		}
		user.LastSignInAt = &value
	}
	if deletionDue.Valid {
		value, parseErr := parseTime(deletionDue.String)
		if parseErr != nil {
			return nil, parseErr
		}
		user.DeletionDueAt = &value
	}
	return &user, nil
}

func newID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("accounts: generate id: %w", err)
	}
	return id.String(), nil
}

func classifyWriteError(operation string, err error) error {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique constraint") || strings.Contains(message, "constraint failed") {
		return fmt.Errorf("%w: %s", ErrConflict, operation)
	}
	return fmt.Errorf("accounts: %s: %w", operation, err)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("accounts: parse timestamp: %w", err)
	}
	return parsed, nil
}
