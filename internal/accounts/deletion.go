package accounts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"arca/internal/audit"
)

const DeletionJobKind = "accounts.delete"

type DeletionMode string

const (
	DeletionTransfer DeletionMode = "transfer"
	DeletionPurge    DeletionMode = "purge"
)

func (m DeletionMode) Valid() bool { return m == DeletionTransfer || m == DeletionPurge }

type DeletionPlan struct {
	Mode             DeletionMode `json:"mode"`
	TransferToUserID string       `json:"transfer_to_user_id,omitempty"`
}

type Deletion struct {
	UserID            string
	Mode              DeletionMode
	TransferToUserID  string
	State             string
	WorkOSUserID      string
	JobID             string
	CreatedBy         string
	DueAt             time.Time
	LocalCompletedAt  *time.Time
	WorkOSCompletedAt *time.Time
	LocalAuditPending bool
	FinalAuditPending bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type deletionJobPayload struct {
	UserID string `json:"user_id"`
}

// IdentityDeletionProvider is intentionally separate from provisioning so
// tests and alternate identity adapters can explicitly opt into destructive
// remote identity deletion.
type IdentityDeletionProvider interface {
	DeleteUser(context.Context, string) error
}

type StagingCleaner interface {
	RemoveStaging(string) error
}

type DeletionJobEnqueuer interface {
	Enqueue(context.Context, string, any, time.Time) (string, error)
}

type DeletionProcessor struct {
	repository *Repository
	identity   IdentityDeletionProvider
	staging    StagingCleaner
	audit      audit.Recorder
}

func NewDeletionProcessor(repository *Repository, identity IdentityDeletionProvider, staging StagingCleaner, recorder audit.Recorder) *DeletionProcessor {
	if recorder == nil {
		recorder = audit.NopRecorder{}
	}
	return &DeletionProcessor{repository: repository, identity: identity, staging: staging, audit: recorder}
}

// EnqueueDueDeletionJobs repairs schedules whose atomic jobs were removed or
// left terminal by an operator. It is intended for startup reconciliation.
func (r *Repository) EnqueueDueDeletionJobs(ctx context.Context, enqueuer DeletionJobEnqueuer) error {
	if enqueuer == nil {
		return errors.New("accounts: deletion job enqueuer is required")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT d.user_id FROM account_deletions d
		LEFT JOIN jobs j ON j.id = d.job_id
		WHERE d.state IN ('scheduled', 'local_complete')
		AND (j.id IS NULL OR j.state IN ('completed', 'failed', 'dead')) ORDER BY d.due_at, d.user_id`)
	if err != nil {
		return fmt.Errorf("accounts: find deletion jobs to reconcile: %w", err)
	}
	var userIDs []string
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			rows.Close()
			return err
		}
		userIDs = append(userIDs, userID)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, userID := range userIDs {
		deletion, err := r.GetDeletion(ctx, userID)
		if err != nil {
			return err
		}
		runAfter := deletion.DueAt
		if deletion.State == "local_complete" {
			runAfter = r.now().UTC()
		}
		jobID, err := enqueuer.Enqueue(ctx, DeletionJobKind, deletionJobPayload{UserID: userID}, runAfter)
		if err != nil {
			return err
		}
		if _, err := r.db.ExecContext(ctx, `UPDATE account_deletions SET job_id = ?, updated_at = ?
			WHERE user_id = ? AND state IN ('scheduled', 'local_complete')`, jobID, formatTime(r.now().UTC()), userID); err != nil {
			return err
		}
	}
	return nil
}

func (p *DeletionProcessor) HandleJob(ctx context.Context, raw json.RawMessage) error {
	var payload deletionJobPayload
	if err := json.Unmarshal(raw, &payload); err != nil || strings.TrimSpace(payload.UserID) == "" {
		return fmt.Errorf("accounts: invalid deletion job payload")
	}
	return p.Process(ctx, payload.UserID)
}

// Process is idempotent. It commits all local ownership work before invoking
// WorkOS, then persists remote completion before allowing the durable job to
// finish. A crash at any boundary safely resumes from the recorded stage.
func (p *DeletionProcessor) Process(ctx context.Context, userID string) error {
	if p == nil || p.repository == nil {
		return errors.New("accounts: deletion repository is required")
	}
	deletion, uploadIDs, err := p.repository.deletionPreparation(ctx, userID)
	if err != nil {
		return err
	}
	if deletion.State == "cancelled" {
		return nil
	}
	if deletion.State == "scheduled" && len(uploadIDs) > 0 {
		if p.staging == nil {
			return errors.New("accounts: staging cleaner is required for account deletion")
		}
		for _, uploadID := range uploadIDs {
			if err := p.staging.RemoveStaging(uploadID); err != nil {
				return fmt.Errorf("accounts: remove staged upload %s: %w", uploadID, err)
			}
		}
	}
	deletion, err = p.repository.finalizeDeletionLocal(ctx, userID)
	if err != nil {
		return err
	}
	if deletion.State == "cancelled" {
		return nil
	}
	if deletion.LocalAuditPending {
		if err := p.record(ctx, deletion, "user.deletion_local_completed"); err != nil {
			return err
		}
		if err := p.repository.markDeletionAudited(ctx, userID, false); err != nil {
			return err
		}
		deletion.LocalAuditPending = false
	}
	if deletion.State == "local_complete" {
		if deletion.WorkOSUserID != "" {
			if p.identity == nil {
				return errors.New("accounts: identity deletion provider is required")
			}
			if err := p.identity.DeleteUser(ctx, deletion.WorkOSUserID); err != nil {
				return fmt.Errorf("accounts: delete WorkOS identity: %w", err)
			}
		}
		deletion, err = p.repository.completeIdentityDeletion(ctx, userID)
		if err != nil {
			return err
		}
	}
	if deletion.FinalAuditPending {
		if err := p.record(ctx, deletion, "user.deleted"); err != nil {
			return err
		}
		if err := p.repository.markDeletionAudited(ctx, userID, true); err != nil {
			return err
		}
	}
	return nil
}

func (p *DeletionProcessor) record(ctx context.Context, deletion Deletion, action string) error {
	actor := deletion.CreatedBy
	metadata := map[string]any{"mode": deletion.Mode, "job_id": deletion.JobID}
	if deletion.TransferToUserID != "" {
		metadata["transfer_to_user_id"] = deletion.TransferToUserID
	}
	if err := p.audit.Record(ctx, audit.Event{
		ActorID: &actor, Action: action, TargetType: "user", TargetID: deletion.UserID, Metadata: metadata,
	}); err != nil {
		return fmt.Errorf("accounts: record deletion audit: %w", err)
	}
	return nil
}

func (r *Repository) ScheduleDeletion(ctx context.Context, userID, actorID string, plan DeletionPlan) (*User, Deletion, error) {
	if !plan.Mode.Valid() || (plan.Mode == DeletionTransfer && strings.TrimSpace(plan.TransferToUserID) == "") ||
		(plan.Mode == DeletionPurge && strings.TrimSpace(plan.TransferToUserID) != "") || plan.TransferToUserID == userID {
		return nil, Deletion{}, fmt.Errorf("%w: deletion requires either a distinct transfer target or purge", ErrInvalidInput)
	}
	now := r.now().UTC()
	due := now.Add(7 * 24 * time.Hour)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, Deletion{}, fmt.Errorf("accounts: begin deletion schedule: %w", err)
	}
	defer tx.Rollback()
	var role, state, workosUserID string
	err = tx.QueryRowContext(ctx, `SELECT role, state, COALESCE(workos_user_id, '') FROM users WHERE id = ?`, userID).Scan(&role, &state, &workosUserID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, Deletion{}, ErrNotFound
	}
	if err != nil {
		return nil, Deletion{}, err
	}
	if state != string(StateActive) && state != string(StateOverQuota) && state != string(StateSuspended) {
		return nil, Deletion{}, ErrInvalidTransition
	}
	if Role(role) == RoleSuperadmin && (State(state) == StateActive || State(state) == StateOverQuota) {
		var others int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id <> ? AND role = 'superadmin' AND state IN ('active', 'over_quota')`, userID).Scan(&others); err != nil {
			return nil, Deletion{}, err
		}
		if others == 0 {
			return nil, Deletion{}, ErrLastSuperadmin
		}
	}
	if plan.Mode == DeletionTransfer {
		var targetState, targetRoot string
		err := tx.QueryRowContext(ctx, `SELECT state, COALESCE(root_node_id, '') FROM users WHERE id = ?`, plan.TransferToUserID).Scan(&targetState, &targetRoot)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, Deletion{}, fmt.Errorf("%w: transfer target does not exist", ErrInvalidInput)
		}
		if err != nil {
			return nil, Deletion{}, err
		}
		if (targetState != string(StateActive) && targetState != string(StateOverQuota)) || targetRoot == "" {
			return nil, Deletion{}, fmt.Errorf("%w: transfer target must be active", ErrInvalidInput)
		}
	}
	var priorState string
	err = tx.QueryRowContext(ctx, `SELECT state FROM account_deletions WHERE user_id = ?`, userID).Scan(&priorState)
	if err == nil && priorState != "cancelled" {
		return nil, Deletion{}, ErrInvalidTransition
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, Deletion{}, err
	}
	jobID, err := newID()
	if err != nil {
		return nil, Deletion{}, err
	}
	payload, _ := json.Marshal(deletionJobPayload{UserID: userID})
	stamp := formatTime(now)
	if _, err := tx.ExecContext(ctx, `INSERT INTO jobs
		(id, kind, payload, state, attempts, max_attempts, run_after, created_at, updated_at)
		VALUES (?, ?, ?, 'queued', 0, 72, ?, ?, ?)`, jobID, DeletionJobKind, string(payload), formatTime(due), stamp, stamp); err != nil {
		return nil, Deletion{}, fmt.Errorf("accounts: enqueue deletion: %w", err)
	}
	var transfer any
	if plan.Mode == DeletionTransfer {
		transfer = plan.TransferToUserID
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO account_deletions
		(user_id, mode, transfer_to_user_id, state, workos_user_id, job_id, created_by, due_at, created_at, updated_at)
		VALUES (?, ?, ?, 'scheduled', ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET mode = excluded.mode, transfer_to_user_id = excluded.transfer_to_user_id,
			state = 'scheduled', workos_user_id = excluded.workos_user_id, job_id = excluded.job_id,
			created_by = excluded.created_by, due_at = excluded.due_at, local_completed_at = NULL,
			workos_completed_at = NULL, local_audited_at = NULL, completed_audited_at = NULL,
			created_at = excluded.created_at, updated_at = excluded.updated_at
		WHERE account_deletions.state = 'cancelled'`, userID, plan.Mode, transfer, nullIfEmpty(workosUserID), jobID, actorID, formatTime(due), stamp, stamp); err != nil {
		return nil, Deletion{}, fmt.Errorf("accounts: persist deletion plan: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET state = 'deletion_pending', deletion_due_at = ?, updated_at = ?
		WHERE id = ? AND state IN ('active', 'over_quota', 'suspended')`, formatTime(due), stamp, userID)
	if err != nil {
		return nil, Deletion{}, err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return nil, Deletion{}, ErrInvalidTransition
	}
	if err := revokeAccountAccessTx(ctx, tx, userID, stamp); err != nil {
		return nil, Deletion{}, err
	}
	if err := tx.Commit(); err != nil {
		return nil, Deletion{}, fmt.Errorf("accounts: commit deletion schedule: %w", err)
	}
	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		return nil, Deletion{}, err
	}
	deletion, err := r.GetDeletion(ctx, userID)
	return user, deletion, err
}

func (r *Repository) GetDeletion(ctx context.Context, userID string) (Deletion, error) {
	return scanDeletion(r.db.QueryRowContext(ctx, deletionSelect+` WHERE user_id = ?`, userID))
}

func (r *Repository) deletionPreparation(ctx context.Context, userID string) (Deletion, []string, error) {
	deletion, err := r.GetDeletion(ctx, userID)
	if err != nil {
		return Deletion{}, nil, err
	}
	if deletion.State != "scheduled" {
		return deletion, nil, nil
	}
	if r.now().UTC().Before(deletion.DueAt) {
		return Deletion{}, nil, ErrDeletionNotDue
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM uploads
		WHERE (owner_id = ? AND state IN ('pending', 'completed', 'cancelled', 'expired', 'failed'))
		   OR (actor_id = ? AND state = 'pending') ORDER BY id`, userID, userID)
	if err != nil {
		return Deletion{}, nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return Deletion{}, nil, err
		}
		ids = append(ids, id)
	}
	return deletion, ids, rows.Err()
}

func (r *Repository) finalizeDeletionLocal(ctx context.Context, userID string) (Deletion, error) {
	now := r.now().UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Deletion{}, fmt.Errorf("accounts: begin local deletion: %w", err)
	}
	defer tx.Rollback()
	deletion, err := scanDeletion(tx.QueryRowContext(ctx, deletionSelect+` WHERE user_id = ?`, userID))
	if err != nil {
		return Deletion{}, err
	}
	if deletion.State != "scheduled" {
		return deletion, nil
	}
	if now.Before(deletion.DueAt) {
		return Deletion{}, ErrDeletionNotDue
	}
	var userState string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM users WHERE id = ?`, userID).Scan(&userState); err != nil {
		return Deletion{}, err
	}
	if userState != string(StateDeletionPending) {
		return Deletion{}, ErrInvalidTransition
	}
	var activeUploads int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM uploads
		WHERE (owner_id = ? OR actor_id = ?) AND state = 'finalizing'`, userID, userID).Scan(&activeUploads); err != nil {
		return Deletion{}, err
	}
	if activeUploads != 0 {
		return Deletion{}, ErrDeletionBusy
	}
	if err := cancelDeletionUploads(ctx, tx, userID, now); err != nil {
		return Deletion{}, err
	}
	if deletion.Mode == DeletionTransfer {
		err = transferOwnedContent(ctx, tx, deletion, now)
	} else {
		err = purgeOwnedContent(ctx, tx, deletion, now)
	}
	if err != nil {
		return Deletion{}, err
	}
	stamp := formatTime(now)
	if _, err := tx.ExecContext(ctx, `UPDATE users SET state = 'deleted', root_node_id = NULL,
		used_bytes = 0, reserved_bytes = 0, deletion_due_at = NULL, updated_at = ? WHERE id = ?`, stamp, userID); err != nil {
		return Deletion{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE account_deletions SET state = 'local_complete', local_completed_at = ?, updated_at = ?
		WHERE user_id = ? AND state = 'scheduled'`, stamp, stamp, userID); err != nil {
		return Deletion{}, err
	}
	if err := tx.Commit(); err != nil {
		return Deletion{}, fmt.Errorf("accounts: commit local deletion: %w", err)
	}
	return r.GetDeletion(ctx, userID)
}

func transferOwnedContent(ctx context.Context, tx *sql.Tx, deletion Deletion, now time.Time) error {
	var username, sourceRoot string
	if err := tx.QueryRowContext(ctx, `SELECT username, COALESCE(root_node_id, '') FROM users WHERE id = ?`, deletion.UserID).Scan(&username, &sourceRoot); err != nil {
		return err
	}
	var targetRoot, targetState string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(root_node_id, ''), state FROM users WHERE id = ?`, deletion.TransferToUserID).Scan(&targetRoot, &targetState); err != nil {
		return err
	}
	if sourceRoot == "" || targetRoot == "" || (targetState != string(StateActive) && targetState != string(StateOverQuota)) {
		return fmt.Errorf("%w: transfer source or target is unavailable", ErrInvalidTransition)
	}
	name, nameKey, err := transferredRootName(ctx, tx, deletion.TransferToUserID, targetRoot, username)
	if err != nil {
		return err
	}
	if err := deletePrivateAccountMetadata(ctx, tx, deletion.UserID); err != nil {
		return err
	}
	stamp := formatTime(now)
	if _, err := tx.ExecContext(ctx, `UPDATE nodes SET owner_id = ?, parent_id = ?, name = ?, name_key = ?,
		revision = revision + 1, updated_at = ? WHERE id = ? AND owner_id = ?`, deletion.TransferToUserID, targetRoot, name, nameKey, stamp, sourceRoot, deletion.UserID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE nodes SET owner_id = ?, updated_at = ? WHERE owner_id = ?`, deletion.TransferToUserID, stamp, deletion.UserID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE blobs SET owner_id = ? WHERE owner_id = ? AND ref_count > 0`, deletion.TransferToUserID, deletion.UserID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE users SET
		used_bytes = (SELECT COALESCE(SUM(size_bytes), 0) FROM blobs WHERE owner_id = users.id AND ref_count > 0 AND state = 'ready'),
		reserved_bytes = (SELECT COALESCE(SUM(reserved_bytes), 0) FROM uploads WHERE owner_id = users.id AND state IN ('pending', 'finalizing')),
		state = CASE WHEN quota_unlimited = 0 AND
			(SELECT COALESCE(SUM(size_bytes), 0) FROM blobs WHERE owner_id = users.id AND ref_count > 0 AND state = 'ready') +
			(SELECT COALESCE(SUM(reserved_bytes), 0) FROM uploads WHERE owner_id = users.id AND state IN ('pending', 'finalizing')) > quota_bytes
			THEN 'over_quota' ELSE 'active' END,
		updated_at = ? WHERE id = ?`, stamp, deletion.TransferToUserID)
	return err
}

func transferredRootName(ctx context.Context, tx *sql.Tx, ownerID, parentID, username string) (string, string, error) {
	base := "Transferred from @" + username
	for suffix := 0; suffix <= 10_000; suffix++ {
		name := base
		if suffix > 0 {
			name = fmt.Sprintf("%s (%d)", base, suffix)
		}
		key := fold.String(name)
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE owner_id = ? AND parent_id = ? AND name_key = ? AND trashed_at IS NULL`, ownerID, parentID, key).Scan(&count); err != nil {
			return "", "", err
		}
		if count == 0 {
			return name, key, nil
		}
	}
	return "", "", fmt.Errorf("%w: too many transferred-folder name conflicts", ErrConflict)
}

func purgeOwnedContent(ctx context.Context, tx *sql.Tx, deletion Deletion, now time.Time) error {
	if err := deletePrivateAccountMetadata(ctx, tx, deletion.UserID); err != nil {
		return err
	}
	var inconsistent int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs b WHERE b.owner_id = ? AND b.ref_count <>
		(SELECT COUNT(*) FROM file_versions v WHERE v.blob_id = b.id)`, deletion.UserID).Scan(&inconsistent); err != nil {
		return err
	}
	if inconsistent != 0 {
		return fmt.Errorf("%w: blob references must reconcile before account purge", ErrDeletionBusy)
	}
	var unsettled int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE owner_id = ? AND state NOT IN ('ready', 'deleting')`, deletion.UserID).Scan(&unsettled); err != nil {
		return err
	}
	if unsettled != 0 {
		return fmt.Errorf("%w: blob finalization must settle before account purge", ErrDeletionBusy)
	}
	var blobs int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM blobs WHERE owner_id = ?`, deletion.UserID).Scan(&blobs); err != nil {
		return err
	}
	deleteAfter := now.Add(24 * time.Hour)
	if _, err := tx.ExecContext(ctx, `UPDATE blobs SET ref_count = 0, state = 'deleting', delete_after = ? WHERE owner_id = ?`, formatTime(deleteAfter), deletion.UserID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE owner_id = ?`, deletion.UserID); err != nil {
		return fmt.Errorf("accounts: purge owned nodes: %w", err)
	}
	if blobs > 0 {
		jobID, err := newID()
		if err != nil {
			return err
		}
		stamp := formatTime(now)
		if _, err := tx.ExecContext(ctx, `INSERT INTO jobs(id, kind, payload, state, run_after, created_at, updated_at)
			VALUES (?, 'blobs.gc', '{}', 'queued', ?, ?, ?)`, jobID, formatTime(deleteAfter), stamp, stamp); err != nil {
			return err
		}
	}
	return nil
}

func cancelDeletionUploads(ctx context.Context, tx *sql.Tx, userID string, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, owner_id, reserved_bytes, share_id FROM uploads
		WHERE (owner_id = ? OR actor_id = ?) AND state = 'pending' ORDER BY id`, userID, userID)
	if err != nil {
		return err
	}
	type pendingUpload struct {
		id, ownerID string
		reserved    int64
		shareID     sql.NullString
	}
	var pending []pendingUpload
	for rows.Next() {
		var upload pendingUpload
		if err := rows.Scan(&upload.id, &upload.ownerID, &upload.reserved, &upload.shareID); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, upload)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	stamp := formatTime(now)
	for _, upload := range pending {
		result, err := tx.ExecContext(ctx, `UPDATE uploads SET state = 'cancelled', reserved_bytes = 0,
			error_code = 'account_deleted', updated_at = ? WHERE id = ? AND state = 'pending'`, stamp, upload.id)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return ErrDeletionBusy
		}
		result, err = tx.ExecContext(ctx, `UPDATE users SET reserved_bytes = reserved_bytes - ?, updated_at = ?
			WHERE id = ? AND reserved_bytes >= ?`, upload.reserved, stamp, upload.ownerID, upload.reserved)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return fmt.Errorf("%w: upload reservation is inconsistent", ErrDeletionBusy)
		}
		if upload.shareID.Valid {
			if _, err := tx.ExecContext(ctx, `UPDATE shares SET editor_used_bytes = CASE
				WHEN editor_used_bytes >= ? THEN editor_used_bytes - ? ELSE 0 END, updated_at = ? WHERE id = ?`,
				upload.reserved, upload.reserved, stamp, upload.shareID.String); err != nil {
				return err
			}
		}
	}
	return nil
}

func deletePrivateAccountMetadata(ctx context.Context, tx *sql.Tx, userID string) error {
	statements := []string{
		`DELETE FROM shares WHERE owner_id = ?`,
		`DELETE FROM public_shares WHERE owner_id = ?`,
		`DELETE FROM share_recipients WHERE user_id = ?`,
		`DELETE FROM favorites WHERE user_id = ?`,
		`DELETE FROM notifications WHERE user_id = ?`,
		`DELETE FROM api_tokens WHERE user_id = ?`,
		`DELETE FROM uploads WHERE owner_id = ? AND state IN ('completed', 'cancelled', 'expired', 'failed')`,
		`DELETE FROM revoked_sessions WHERE user_id = ?`,
		`DELETE FROM support_access WHERE actor_id = ? OR target_user_id = ?`,
	}
	for _, statement := range statements {
		args := []any{userID}
		if strings.Count(statement, "?") == 2 {
			args = append(args, userID)
		}
		if _, err := tx.ExecContext(ctx, statement, args...); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) completeIdentityDeletion(ctx context.Context, userID string) (Deletion, error) {
	now := r.now().UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Deletion{}, err
	}
	defer tx.Rollback()
	deletion, err := scanDeletion(tx.QueryRowContext(ctx, deletionSelect+` WHERE user_id = ?`, userID))
	if err != nil {
		return Deletion{}, err
	}
	if deletion.State == "completed" {
		return deletion, nil
	}
	if deletion.State != "local_complete" {
		return Deletion{}, ErrInvalidTransition
	}
	compactID := strings.ReplaceAll(userID, "-", "")
	username := "deleted-" + compactID
	email := username + "@deleted.invalid"
	stamp := formatTime(now)
	if _, err := tx.ExecContext(ctx, `UPDATE users SET workos_user_id = NULL, username = ?, username_key = ?,
		email = ?, email_key = ?, display_name = NULL, updated_at = ? WHERE id = ? AND state = 'deleted'`,
		username, username, email, email, stamp, userID); err != nil {
		return Deletion{}, classifyWriteError("anonymize deleted user", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE account_deletions SET state = 'completed', workos_completed_at = ?, updated_at = ?
		WHERE user_id = ? AND state = 'local_complete'`, stamp, stamp, userID); err != nil {
		return Deletion{}, err
	}
	if err := tx.Commit(); err != nil {
		return Deletion{}, err
	}
	return r.GetDeletion(ctx, userID)
}

func (r *Repository) markDeletionAudited(ctx context.Context, userID string, final bool) error {
	column := "local_audited_at"
	state := "local_complete"
	if final {
		column = "completed_audited_at"
		state = "completed"
	}
	stamp := formatTime(r.now().UTC())
	result, err := r.db.ExecContext(ctx, `UPDATE account_deletions SET `+column+` = COALESCE(`+column+`, ?), updated_at = ?
		WHERE user_id = ? AND state = ?`, stamp, stamp, userID, state)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrInvalidTransition
	}
	return nil
}

const deletionSelect = `SELECT user_id, mode, COALESCE(transfer_to_user_id, ''), state,
	COALESCE(workos_user_id, ''), job_id, created_by, due_at, local_completed_at,
	workos_completed_at, local_audited_at, completed_audited_at, created_at, updated_at
	FROM account_deletions`

func scanDeletion(row interface{ Scan(...any) error }) (Deletion, error) {
	var deletion Deletion
	var mode, due, created, updated string
	var localCompleted, workosCompleted, localAudited, completedAudited sql.NullString
	err := row.Scan(&deletion.UserID, &mode, &deletion.TransferToUserID, &deletion.State,
		&deletion.WorkOSUserID, &deletion.JobID, &deletion.CreatedBy, &due, &localCompleted,
		&workosCompleted, &localAudited, &completedAudited, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Deletion{}, ErrNotFound
	}
	if err != nil {
		return Deletion{}, err
	}
	deletion.Mode = DeletionMode(mode)
	var parseErr error
	if deletion.DueAt, parseErr = parseTime(due); parseErr != nil {
		return Deletion{}, parseErr
	}
	if deletion.CreatedAt, parseErr = parseTime(created); parseErr != nil {
		return Deletion{}, parseErr
	}
	if deletion.UpdatedAt, parseErr = parseTime(updated); parseErr != nil {
		return Deletion{}, parseErr
	}
	if localCompleted.Valid {
		value, err := parseTime(localCompleted.String)
		if err != nil {
			return Deletion{}, err
		}
		deletion.LocalCompletedAt = &value
	}
	if workosCompleted.Valid {
		value, err := parseTime(workosCompleted.String)
		if err != nil {
			return Deletion{}, err
		}
		deletion.WorkOSCompletedAt = &value
	}
	deletion.LocalAuditPending = deletion.State == "local_complete" && !localAudited.Valid
	deletion.FinalAuditPending = deletion.State == "completed" && !completedAudited.Valid
	return deletion, nil
}
