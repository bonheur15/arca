package uploads

import (
	"context"
	"errors"
	"time"

	"arca/internal/files"
)

// Expire releases quota and removes staging files for expired pending uploads.
func (s *Service) Expire(ctx context.Context, limit int) (int, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM uploads
		WHERE state = 'pending' AND expires_at <= ? ORDER BY expires_at LIMIT ?`, timeText(s.now()), limit)
	if err != nil {
		return 0, files.WrapError(files.CodeInvalid, "expire uploads", "", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	var errs []error
	completed := 0
	for _, id := range ids {
		unlock := s.locks.lock(id)
		upload, getErr := getUpload(ctx, s.db.Reader(), id)
		if getErr == nil && upload.State == StatePending && !s.now().Before(upload.ExpiresAt) {
			getErr = s.expireLocked(ctx, upload)
			if getErr == nil {
				completed++
			}
		}
		unlock()
		if getErr != nil {
			errs = append(errs, getErr)
		}
	}
	return completed, errors.Join(errs...)
}

// CollectGarbage removes immutable blobs only after their refcount reached
// zero and the 24-hour grace timestamp has elapsed. Filesystem deletion comes
// first, making a crash safely retryable.
func (s *Service) CollectGarbage(ctx context.Context, limit int) (int, error) {
	var backupLease int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM operation_leases WHERE name = 'backup' AND lease_until > ?`, timeText(s.now())).Scan(&backupLease); err != nil {
		return 0, files.WrapError(files.CodeInvalid, "check backup lease", "", err)
	}
	if backupLease != 0 {
		return 0, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, storage_key FROM blobs
		WHERE state = 'deleting' AND ref_count = 0 AND delete_after IS NOT NULL AND delete_after <= ?
		ORDER BY delete_after, id LIMIT ?`, timeText(s.now()), limit)
	if err != nil {
		return 0, files.WrapError(files.CodeInvalid, "collect blob garbage", "", err)
	}
	type candidate struct{ id, key string }
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.key); err != nil {
			rows.Close()
			return 0, err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	deleted := 0
	var errs []error
	for _, item := range candidates {
		if err := s.storage.RemoveBlob(item.key); err != nil {
			errs = append(errs, files.WrapError(files.CodeInvalid, "remove garbage blob", item.id, err))
			continue
		}
		result, err := s.db.Writer().ExecContext(ctx, `DELETE FROM blobs
			WHERE id = ? AND storage_key = ? AND state = 'deleting' AND ref_count = 0 AND delete_after <= ?`,
			item.id, item.key, timeText(s.now()))
		if err != nil {
			errs = append(errs, files.WrapError(files.CodeInvalid, "delete garbage metadata", item.id, err))
			continue
		}
		if affected, _ := result.RowsAffected(); affected == 1 {
			deleted++
		}
	}
	return deleted, errors.Join(errs...)
}

func (s *Service) cleanupTerminalStaging(ctx context.Context) error {
	cutoff := timeText(s.now().Add(-time.Hour))
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM uploads
		WHERE state IN ('completed', 'cancelled', 'expired', 'failed') AND updated_at <= ?`, cutoff)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		errs = appendIf(errs, s.storage.RemoveStaging(id))
	}
	return errors.Join(errs...)
}
