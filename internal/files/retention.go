package files

import (
	"context"
	"errors"
	"time"
)

type RetentionResult struct {
	VersionsDeleted int64 `json:"versions_deleted"`
	BlobsQueued     int64 `json:"blobs_queued"`
	BytesReleased   int64 `json:"bytes_released"`
}

// PruneVersions enforces Arca's dual retention rule: a version is eligible
// only when it is older than 30 days and outside the newest ten for its file.
func (s *Service) PruneVersions(ctx context.Context, ownerID string, limit int) (RetentionResult, error) {
	const op = "prune file versions"
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return RetentionResult{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	cutoff := timeText(s.now().Add(-30 * 24 * time.Hour))
	rows, err := tx.QueryContext(ctx, `WITH ranked AS (
		SELECT v.id, v.blob_id, v.node_id, v.size_bytes,
			ROW_NUMBER() OVER (PARTITION BY v.node_id ORDER BY v.sequence DESC) AS position,
			n.current_version_id
		FROM file_versions v JOIN nodes n ON n.id = v.node_id
		WHERE n.owner_id = ?
	) SELECT ranked.id, ranked.blob_id FROM ranked JOIN file_versions v ON v.id = ranked.id
	WHERE ranked.position > 10 AND v.created_at < ? AND ranked.id <> ranked.current_version_id
	ORDER BY v.created_at, ranked.id LIMIT ?`, ownerID, cutoff, limit)
	if err != nil {
		return RetentionResult{}, WrapError(CodeInvalid, op, ownerID, err)
	}
	type candidate struct{ id, blobID string }
	var candidates []candidate
	counts := make(map[string]int64)
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.blobID); err != nil {
			rows.Close()
			return RetentionResult{}, err
		}
		candidates = append(candidates, item)
		counts[item.blobID]++
	}
	if err := rows.Close(); err != nil {
		return RetentionResult{}, err
	}
	if len(candidates) == 0 {
		_ = tx.Rollback(ctx)
		return RetentionResult{}, nil
	}
	deleteAfter := timeText(s.now().Add(24 * time.Hour))
	result := RetentionResult{VersionsDeleted: int64(len(candidates))}
	for blobID, count := range counts {
		var refs, size int64
		if err := tx.QueryRowContext(ctx, "SELECT ref_count, size_bytes FROM blobs WHERE id = ?", blobID).Scan(&refs, &size); err != nil {
			return RetentionResult{}, err
		}
		if refs < count {
			return RetentionResult{}, NewError(CodeInvalidState, op, blobID, "blob reference count is inconsistent")
		}
		if refs == count {
			result.BlobsQueued++
			result.BytesReleased += size
		}
		if _, err := tx.ExecContext(ctx, `UPDATE blobs SET ref_count = ref_count - ?,
			state = CASE WHEN ref_count <= ? THEN 'deleting' ELSE state END,
			delete_after = CASE WHEN ref_count <= ? THEN ? ELSE delete_after END
			WHERE id = ? AND ref_count >= ?`, count, count, count, deleteAfter, blobID, count); err != nil {
			return RetentionResult{}, err
		}
	}
	for _, item := range candidates {
		if _, err := tx.ExecContext(ctx, "DELETE FROM file_versions WHERE id = ?", item.id); err != nil {
			return RetentionResult{}, err
		}
	}
	if result.BytesReleased > 0 {
		quotaResult, err := tx.ExecContext(ctx, `UPDATE users SET used_bytes = used_bytes - ?, updated_at = ?
			WHERE id = ? AND used_bytes >= ?`, result.BytesReleased, timeText(s.now()), ownerID, result.BytesReleased)
		if err != nil {
			return RetentionResult{}, err
		}
		if affected, _ := quotaResult.RowsAffected(); affected != 1 {
			return RetentionResult{}, NewError(CodeInvalidState, op, ownerID, "used-byte accounting is inconsistent")
		}
	}
	if result.BlobsQueued > 0 {
		jobID, err := s.newID()
		if err != nil {
			return RetentionResult{}, err
		}
		now := timeText(s.now())
		if _, err := tx.ExecContext(ctx, `INSERT INTO jobs(id, kind, payload, state, run_after, created_at, updated_at)
			VALUES (?, 'blobs.gc', '{}', 'queued', ?, ?, ?)`, jobID, deleteAfter, now, now); err != nil {
			return RetentionResult{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return RetentionResult{}, err
	}
	return result, nil
}

// PurgeExpiredTrash permanently purges owner trash roots older than 30 days.
// Each root is isolated so one conflict does not block unrelated cleanup.
func (s *Service) PurgeExpiredTrash(ctx context.Context, ownerID string, limit int) (int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, revision FROM nodes
		WHERE owner_id = ? AND trashed_at IS NOT NULL AND trashed_at <= ?
		ORDER BY trashed_at, id LIMIT ?`, ownerID, timeText(s.now().Add(-30*24*time.Hour)), limit)
	if err != nil {
		return 0, WrapError(CodeInvalid, "purge expired trash", ownerID, err)
	}
	type candidate struct {
		id       string
		revision int64
	}
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.revision); err != nil {
			rows.Close()
			return 0, err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	completed := 0
	var errs []error
	for _, item := range candidates {
		if _, err := s.Purge(ctx, ownerID, item.id, item.revision); err != nil {
			errs = append(errs, err)
		} else {
			completed++
		}
	}
	return completed, errors.Join(errs...)
}
