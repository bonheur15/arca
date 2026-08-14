package files

import (
	"context"
	"database/sql"
	"errors"

	"arca/internal/database"
)

type QuotaStatus struct {
	OwnerID             string `json:"owner_id"`
	QuotaBytes          int64  `json:"quota_bytes"`
	Unlimited           bool   `json:"unlimited"`
	StoredUsedBytes     int64  `json:"stored_used_bytes"`
	ActualUsedBytes     int64  `json:"actual_used_bytes"`
	StoredReservedBytes int64  `json:"stored_reserved_bytes"`
	ActualReservedBytes int64  `json:"actual_reserved_bytes"`
	Drift               bool   `json:"drift"`
}

// Quota computes authoritative physical blob and upload-reservation usage.
func (s *Service) Quota(ctx context.Context, ownerID string) (QuotaStatus, error) {
	return quotaStatus(ctx, s.db.Reader(), ownerID)
}

// ReconcileQuota atomically repairs cached quota counters and active/over-quota
// state. It never changes suspended, provisioning, or deletion states.
func (s *Service) ReconcileQuota(ctx context.Context, ownerID string) (QuotaStatus, error) {
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return QuotaStatus{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	status, err := quotaStatus(ctx, tx, ownerID)
	if err != nil {
		return QuotaStatus{}, err
	}
	state := "active"
	if !status.Unlimited && (status.ActualUsedBytes > status.QuotaBytes ||
		status.ActualReservedBytes > status.QuotaBytes-status.ActualUsedBytes) {
		state = "over_quota"
	}
	_, err = tx.ExecContext(ctx, `UPDATE users SET used_bytes = ?, reserved_bytes = ?,
		state = CASE WHEN state IN ('active', 'over_quota') THEN ? ELSE state END, updated_at = ? WHERE id = ?`,
		status.ActualUsedBytes, status.ActualReservedBytes, state, timeText(s.now()), ownerID)
	if err != nil {
		return QuotaStatus{}, WrapError(CodeInvalid, "reconcile quota", ownerID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return QuotaStatus{}, err
	}
	status.StoredUsedBytes = status.ActualUsedBytes
	status.StoredReservedBytes = status.ActualReservedBytes
	status.Drift = false
	return status, nil
}

func quotaStatus(ctx context.Context, q database.Queryer, ownerID string) (QuotaStatus, error) {
	var status QuotaStatus
	status.OwnerID = ownerID
	var unlimited int
	err := q.QueryRowContext(ctx, `SELECT u.quota_bytes, u.quota_unlimited, u.used_bytes, u.reserved_bytes,
		(SELECT COALESCE(SUM(size_bytes), 0) FROM blobs WHERE owner_id = u.id AND ref_count > 0 AND state = 'ready'),
		(SELECT COALESCE(SUM(reserved_bytes), 0) FROM uploads WHERE owner_id = u.id AND state IN ('pending', 'finalizing'))
		FROM users u WHERE u.id = ?`, ownerID).Scan(&status.QuotaBytes, &unlimited, &status.StoredUsedBytes,
		&status.StoredReservedBytes, &status.ActualUsedBytes, &status.ActualReservedBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return QuotaStatus{}, NewError(CodeNotFound, "read quota", ownerID, "user not found")
	}
	if err != nil {
		return QuotaStatus{}, WrapError(CodeInvalid, "read quota", ownerID, err)
	}
	status.Unlimited = unlimited == 1
	status.Drift = status.StoredUsedBytes != status.ActualUsedBytes || status.StoredReservedBytes != status.ActualReservedBytes
	return status, nil
}
