package uploads

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"arca/internal/database"
	"arca/internal/files"
)

func (s *Service) finalizeLocked(ctx context.Context, uploadID string) (Upload, error) {
	upload, err := getUpload(ctx, s.db.Reader(), uploadID)
	if err != nil {
		return Upload{}, err
	}
	if upload.State == StateCompleted {
		return upload, nil
	}
	if upload.State != StatePending && upload.State != StateFinalizing {
		return Upload{}, files.NewError(files.CodeInvalidState, "finalize upload", uploadID, "upload is not finalizable")
	}
	if upload.CommittedBytes != upload.ExpectedBytes {
		return Upload{}, files.NewError(files.CodeInvalidState, "finalize upload", uploadID, "upload is incomplete")
	}
	if s.hook != nil {
		if err := s.hook(ctx, BeforeStateFinalizing, upload); err != nil {
			return Upload{}, err
		}
	}
	blobKey := ""
	if upload.intendedBlobKey != nil {
		blobKey = *upload.intendedBlobKey
	}
	if blobKey == "" {
		blobKey, err = s.newID()
		if err != nil {
			return Upload{}, err
		}
		result, err := s.db.Writer().ExecContext(ctx, `UPDATE uploads SET state = 'finalizing', intended_blob_key = ?, updated_at = ?
            WHERE id = ? AND state = 'pending' AND committed_bytes = expected_bytes`, blobKey, timeText(s.now()), uploadID)
		if err != nil {
			return Upload{}, err
		}
		affected, _ := result.RowsAffected()
		if affected != 1 {
			upload, err = getUpload(ctx, s.db.Reader(), uploadID)
			if err != nil || upload.State != StateFinalizing {
				return Upload{}, files.NewError(files.CodeInvalidState, "finalize upload", uploadID, "state changed concurrently")
			}
			if upload.intendedBlobKey == nil {
				return Upload{}, files.NewError(files.CodeInvalidState, "finalize upload", uploadID, "blob key is missing")
			}
			blobKey = *upload.intendedBlobKey
		}
		upload.State = StateFinalizing
		upload.intendedBlobKey = &blobKey
	}
	if s.hook != nil {
		if err := s.hook(ctx, AfterStateFinalizing, upload); err != nil {
			return Upload{}, err
		}
	}

	reader, err := s.storage.OpenStagingRead(uploadID)
	if err == nil {
		hash := sha256.New()
		size, copyErr := io.Copy(hash, reader)
		closeErr := reader.Close()
		if copyErr != nil || closeErr != nil {
			return Upload{}, errors.Join(copyErr, closeErr)
		}
		if size != upload.ExpectedBytes {
			return Upload{}, s.failUpload(ctx, upload, "staging_size_mismatch", fmt.Errorf("staging size %d, expected %d", size, upload.ExpectedBytes))
		}
		uploadChecksum := hex.EncodeToString(hash.Sum(nil))
		mimeType, mimeErr := detectMIME(s.storage, uploadID, false)
		if mimeErr != nil {
			return Upload{}, mimeErr
		}
		if err := s.storage.Finalize(uploadID, blobKey); err != nil {
			return Upload{}, files.WrapError(files.CodeInvalid, "finalize upload", uploadID, err)
		}
		if s.hook != nil {
			if err := s.hook(ctx, AfterBlobRename, upload); err != nil {
				return Upload{}, err
			}
		}
		return s.finishMetadata(ctx, upload, blobKey, uploadChecksum, mimeType)
	}

	// A missing staging file after state=finalizing may mean the atomic rename
	// succeeded before a crash. Re-hash the intended blob and finish idempotently.
	blob, blobErr := s.storage.OpenBlob(blobKey)
	if blobErr != nil {
		return Upload{}, files.WrapError(files.CodeInvalidState, "recover upload finalization", uploadID, errors.Join(err, blobErr))
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, blob)
	closeErr := blob.Close()
	if copyErr != nil || closeErr != nil || size != upload.ExpectedBytes {
		_ = s.storage.QuarantineBlob(blobKey)
		return Upload{}, s.failUpload(ctx, upload, "blob_verification_failed", errors.Join(copyErr, closeErr))
	}
	mimeType, mimeErr := detectMIME(s.storage, blobKey, true)
	if mimeErr != nil {
		return Upload{}, mimeErr
	}
	return s.finishMetadata(ctx, upload, blobKey, hex.EncodeToString(hash.Sum(nil)), mimeType)
}

func (s *Service) finishMetadata(ctx context.Context, upload Upload, blobKey, checksum, mimeType string) (Upload, error) {
	completed, err := s.commitMetadata(ctx, upload, blobKey, checksum, mimeType)
	if err == nil {
		return completed, nil
	}
	code := files.ErrorCodeOf(err)
	if code != files.CodeConflict && code != files.CodeRevisionMismatch {
		return Upload{}, err
	}
	quarantineErr := s.storage.QuarantineBlob(blobKey)
	errorCode := "name_conflict"
	if code == files.CodeRevisionMismatch {
		errorCode = "revision_mismatch"
	}
	failErr := s.failUpload(ctx, upload, errorCode, err)
	return Upload{}, errors.Join(failErr, quarantineErr)
}

func detectMIME(storage Storage, key string, blob bool) (string, error) {
	var reader io.ReadCloser
	var err error
	if blob {
		reader, err = storage.OpenBlob(key)
	} else {
		reader, err = storage.OpenStagingRead(key)
	}
	if err != nil {
		return "", err
	}
	defer reader.Close()
	buffer := make([]byte, 512)
	read, readErr := io.ReadFull(reader, buffer)
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return "", readErr
	}
	return http.DetectContentType(buffer[:read]), nil
}

func (s *Service) commitMetadata(ctx context.Context, upload Upload, blobKey, checksum, mimeType string) (Upload, error) {
	if s.hook != nil {
		if err := s.hook(ctx, BeforeMetadataCommit, upload); err != nil {
			return Upload{}, err
		}
	}
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return Upload{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	current, err := getUpload(ctx, tx, upload.ID)
	if err != nil {
		return Upload{}, err
	}
	if current.State == StateCompleted {
		_ = tx.Rollback(ctx)
		return current, nil
	}
	if current.State != StateFinalizing || current.intendedBlobKey == nil || *current.intendedBlobKey != blobKey {
		return Upload{}, files.NewError(files.CodeInvalidState, "commit upload", upload.ID, "finalization identity changed")
	}
	now := timeText(s.now())
	blobID, err := s.newID()
	if err != nil {
		return Upload{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO blobs
        (id, owner_id, storage_key, size_bytes, sha256, state, ref_count, created_at)
        VALUES (?, ?, ?, ?, ?, 'ready', 1, ?)`, blobID, current.OwnerID, blobKey, current.ExpectedBytes, checksum, now); err != nil {
		return Upload{}, files.WrapError(files.CodeConflict, "commit upload blob", blobKey, err)
	}
	nodeID := ""
	versionID, err := s.newID()
	if err != nil {
		return Upload{}, err
	}
	sequence := int64(1)
	if current.ReplaceNodeID != nil {
		if current.ReplaceRevision == nil {
			return Upload{}, files.NewError(files.CodeInvalidState, "commit upload", current.ID, "replacement revision is missing")
		}
		nodeID = *current.ReplaceNodeID
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(sequence), 0) + 1 FROM file_versions WHERE node_id = ?", nodeID).Scan(&sequence); err != nil {
			return Upload{}, err
		}
	} else {
		if current.ConflictMode == ConflictKeepBoth {
			var exists int
			err := tx.QueryRowContext(ctx, `SELECT 1 FROM nodes
				WHERE owner_id = ? AND parent_id = ? AND name_key = ? AND trashed_at IS NULL`,
				current.OwnerID, current.ParentID, nameKey(current.Name)).Scan(&exists)
			if err == nil {
				available, availableKey, chooseErr := chooseAvailableName(ctx, tx, current.OwnerID, current.ParentID, current.Name, current.ID)
				if chooseErr != nil {
					return Upload{}, chooseErr
				}
				current.Name = available
				if _, err := tx.ExecContext(ctx, "UPDATE uploads SET name = ?, name_key = ? WHERE id = ?", available, availableKey, current.ID); err != nil {
					return Upload{}, err
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				return Upload{}, err
			}
		}
		nodeID, err = s.newID()
		if err != nil {
			return Upload{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO nodes
            (id, owner_id, parent_id, kind, name, name_key, mime_type, size_bytes, current_version_id,
             revision, created_by, created_at, updated_at)
            VALUES (?, ?, ?, 'file', ?, ?, ?, ?, ?, 1, ?, ?, ?)`, nodeID, current.OwnerID, current.ParentID,
			current.Name, nameKey(current.Name), mimeType, current.ExpectedBytes, versionID, current.ActorID, now, now); err != nil {
			return Upload{}, files.WrapError(files.CodeConflict, "commit upload node", nodeID, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO file_versions
        (id, node_id, blob_id, sequence, size_bytes, sha256, mime_type, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, versionID, nodeID, blobID, sequence, current.ExpectedBytes, checksum, mimeType, current.ActorID, now); err != nil {
		return Upload{}, err
	}
	if current.ReplaceNodeID != nil {
		result, err := tx.ExecContext(ctx, `UPDATE nodes SET current_version_id = ?, size_bytes = ?, mime_type = ?,
			revision = revision + 1, updated_at = ? WHERE id = ? AND revision = ? AND trashed_at IS NULL`,
			versionID, current.ExpectedBytes, mimeType, now, nodeID, *current.ReplaceRevision)
		if err != nil {
			return Upload{}, err
		}
		affected, _ := result.RowsAffected()
		if affected != 1 {
			return Upload{}, files.NewError(files.CodeRevisionMismatch, "commit upload", nodeID, "replacement target changed since upload creation")
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE users SET reserved_bytes = reserved_bytes - ?, used_bytes = used_bytes + ?, updated_at = ?
        WHERE id = ? AND reserved_bytes >= ?`, current.ReservedBytes, current.ExpectedBytes, now, current.OwnerID, current.ReservedBytes)
	if err != nil {
		return Upload{}, err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return Upload{}, files.NewError(files.CodeInvalidState, "commit upload", current.OwnerID, "quota reservation is inconsistent")
	}
	result, err = tx.ExecContext(ctx, `UPDATE uploads SET state = 'completed', reserved_bytes = 0, error_code = NULL, updated_at = ?
        WHERE id = ? AND state = 'finalizing'`, now, current.ID)
	if err != nil {
		return Upload{}, err
	}
	affected, _ = result.RowsAffected()
	if affected != 1 {
		return Upload{}, files.NewError(files.CodeInvalidState, "commit upload", current.ID, "upload changed concurrently")
	}
	if err := tx.Commit(ctx); err != nil {
		return Upload{}, err
	}
	completed, err := s.Head(ctx, current.ActorID, current.ID)
	if err != nil {
		return Upload{}, err
	}
	completed.NodeID = &nodeID
	completed.CurrentVersionID = &versionID
	return completed, nil
}

func nameKey(name string) string { _, key, _ := files.NormalizeName(name); return key }

// Reconcile repairs staging tails and completes uploads left in finalizing by a
// process crash. It is safe to call at every startup.
func (s *Service) Reconcile(ctx context.Context) error {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM uploads WHERE state IN ('pending', 'finalizing') ORDER BY created_at`)
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
		unlock := s.locks.lock(id)
		upload, getErr := getUpload(ctx, s.db.Reader(), id)
		if getErr != nil {
			errs = append(errs, getErr)
			unlock()
			continue
		}
		if upload.State == StatePending {
			if !s.now().Before(upload.ExpiresAt) {
				errs = appendIf(errs, s.expireLocked(ctx, upload))
			} else if size, sizeErr := s.storage.StagingSize(id); sizeErr != nil {
				errs = append(errs, sizeErr)
			} else if size > upload.CommittedBytes {
				errs = appendIf(errs, s.storage.TruncateStaging(id, upload.CommittedBytes))
			} else if size < upload.CommittedBytes {
				errs = append(errs, s.failUpload(ctx, upload, "staging_truncated", fmt.Errorf("staging size %d, committed %d", size, upload.CommittedBytes)))
			}
		} else {
			_, finalizeErr := s.finalizeLocked(ctx, id)
			errs = appendIf(errs, finalizeErr)
		}
		unlock()
	}
	if err := s.quarantineUnexpected(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := s.cleanupTerminalStaging(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (s *Service) quarantineUnexpected(ctx context.Context) error {
	known := make(map[string]struct{})
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT storage_key FROM blobs
		UNION SELECT intended_blob_key FROM uploads WHERE state = 'finalizing' AND intended_blob_key IS NOT NULL`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			rows.Close()
			return err
		}
		known[key] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	keys, err := s.storage.ListBlobKeys()
	if err != nil {
		return err
	}
	var errs []error
	for _, key := range keys {
		if _, ok := known[key]; !ok {
			errs = appendIf(errs, s.storage.QuarantineBlob(key))
		}
	}
	return errors.Join(errs...)
}

func appendIf(values []error, err error) []error {
	if err != nil {
		return append(values, err)
	}
	return values
}

func getUpload(ctx context.Context, q database.Queryer, id string) (Upload, error) {
	var upload Upload
	var replaceID, shareID, errorCode, blobKey sql.NullString
	var replaceRevision sql.NullInt64
	var expires, created, updated string
	err := q.QueryRowContext(ctx, `SELECT id, actor_id, owner_id, parent_id, name, expected_bytes,
		committed_bytes, reserved_bytes, staging_key, intended_blob_key, conflict_mode, replace_node_id, replace_revision,
        share_id, state, error_code, expires_at, created_at, updated_at
        FROM uploads WHERE id = ?`, id).Scan(&upload.ID, &upload.ActorID, &upload.OwnerID, &upload.ParentID,
		&upload.Name, &upload.ExpectedBytes, &upload.CommittedBytes, &upload.ReservedBytes, &upload.stagingKey,
		&blobKey, &upload.ConflictMode, &replaceID, &replaceRevision, &shareID, &upload.State, &errorCode, &expires, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return Upload{}, files.NewError(files.CodeNotFound, "get upload", id, "upload not found")
	}
	if err != nil {
		return Upload{}, files.WrapError(files.CodeInvalid, "get upload", id, err)
	}
	if replaceID.Valid {
		upload.ReplaceNodeID = &replaceID.String
	}
	if replaceRevision.Valid {
		upload.ReplaceRevision = &replaceRevision.Int64
	}
	if shareID.Valid {
		upload.ShareID = &shareID.String
	}
	if errorCode.Valid {
		upload.ErrorCode = &errorCode.String
	}
	if blobKey.Valid {
		upload.intendedBlobKey = &blobKey.String
	}
	upload.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return Upload{}, err
	}
	upload.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return Upload{}, err
	}
	upload.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return Upload{}, err
	}
	if upload.State == StateCompleted && upload.intendedBlobKey != nil {
		var nodeID, versionID string
		err := q.QueryRowContext(ctx, `SELECT v.node_id, v.id FROM blobs b
			JOIN file_versions v ON v.blob_id = b.id
			WHERE b.storage_key = ? ORDER BY v.sequence DESC LIMIT 1`, *upload.intendedBlobKey).Scan(&nodeID, &versionID)
		if err == nil {
			upload.NodeID = &nodeID
			upload.CurrentVersionID = &versionID
		} else if !errors.Is(err, sql.ErrNoRows) {
			return Upload{}, err
		}
	}
	return upload, nil
}
