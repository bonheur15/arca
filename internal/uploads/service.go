package uploads

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"

	"arca/internal/database"
	"arca/internal/files"
	"github.com/google/uuid"
)

type Service struct {
	db       *database.DB
	storage  Storage
	locks    keyedLocks
	now      func() time.Time
	newID    func() (string, error)
	ttl      time.Duration
	maxChunk int64
	hook     FinalizeHook
}

type ServiceOptions struct {
	Now           func() time.Time
	NewID         func() (string, error)
	TTL           time.Duration
	MaxChunkBytes int64
	FinalizeHook  FinalizeHook
}

func NewService(db *database.DB, storage Storage, opts ServiceOptions) *Service {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	newID := opts.NewID
	if newID == nil {
		newID = func() (string, error) { id, err := uuid.NewV7(); return id.String(), err }
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	maxChunk := opts.MaxChunkBytes
	if maxChunk <= 0 {
		maxChunk = DefaultMaxChunk
	}
	return &Service{db: db, storage: storage, now: now, newID: newID, ttl: ttl, maxChunk: maxChunk, hook: opts.FinalizeHook}
}

func (s *Service) Create(ctx context.Context, request CreateRequest) (Upload, error) {
	const op = "create upload"
	if request.ExpectedBytes < 0 {
		return Upload{}, files.NewError(files.CodeInvalid, op, "", "upload length cannot be negative")
	}
	if request.ConflictMode == "" {
		request.ConflictMode = ConflictFail
	}
	if request.ConflictMode != ConflictFail && request.ConflictMode != ConflictKeepBoth && request.ConflictMode != ConflictReplace {
		return Upload{}, files.NewError(files.CodeInvalid, op, "", "invalid conflict mode")
	}
	display, key, err := files.NormalizeName(request.Name)
	if err != nil {
		return Upload{}, err
	}
	id, err := s.newID()
	if err != nil {
		return Upload{}, err
	}
	now := s.now().UTC()
	expires := now.Add(s.ttl)
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return Upload{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	access, err := files.Authorize(ctx, tx, request.ActorID, request.ParentID, files.ActionCreateChild, now)
	if err != nil {
		return Upload{}, err
	}
	var parentKind string
	if err := tx.QueryRowContext(ctx, "SELECT kind FROM nodes WHERE id = ?", request.ParentID).Scan(&parentKind); err != nil || parentKind != "folder" {
		return Upload{}, files.NewError(files.CodeInvalid, op, request.ParentID, "parent is not a folder")
	}
	var maxFile sql.NullInt64
	var maxPending int
	var used, reserved, quota int64
	var unlimited int
	var ownerState string
	var maxItems, itemCount int64
	err = tx.QueryRowContext(ctx, `SELECT p.max_file_bytes, p.max_pending_uploads,
		u.used_bytes, u.reserved_bytes, u.quota_bytes, u.quota_unlimited, u.state, p.max_items,
		(SELECT COUNT(*) FROM nodes WHERE owner_id = u.id)
		FROM users u JOIN user_policies p ON p.user_id = u.id WHERE u.id = ?`, access.OwnerID).Scan(
		&maxFile, &maxPending, &used, &reserved, &quota, &unlimited, &ownerState, &maxItems, &itemCount)
	if err != nil {
		return Upload{}, files.WrapError(files.CodeInvalid, op, access.OwnerID, err)
	}
	if maxFile.Valid && request.ExpectedBytes > maxFile.Int64 {
		return Upload{}, files.NewError(files.CodeQuota, op, "", "file exceeds the account file-size limit")
	}
	if ownerState == "over_quota" {
		return Upload{}, files.NewError(files.CodeQuota, op, access.OwnerID, "account is over quota")
	}
	if request.ConflictMode != ConflictReplace && itemCount+1 > maxItems {
		return Upload{}, files.NewError(files.CodeItemLimit, op, access.OwnerID, "item limit would be exceeded")
	}
	var pending int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM uploads WHERE owner_id = ? AND state IN ('pending', 'finalizing')", access.OwnerID).Scan(&pending); err != nil {
		return Upload{}, err
	}
	if pending >= maxPending {
		return Upload{}, files.NewError(files.CodeUploadLimit, op, access.OwnerID, "too many pending uploads")
	}
	if unlimited == 0 && (request.ExpectedBytes > quota || used > quota-request.ExpectedBytes || reserved > quota-request.ExpectedBytes-used) {
		return Upload{}, files.NewError(files.CodeQuota, op, access.OwnerID, "storage quota would be exceeded")
	}
	free, err := s.storage.FreeBytes()
	if err != nil {
		return Upload{}, files.WrapError(files.CodeInvalid, op, "", err)
	}
	var filesystemReserve int64
	if err := tx.QueryRowContext(ctx, "SELECT filesystem_reserve_bytes FROM instance_settings WHERE singleton = 1").Scan(&filesystemReserve); err != nil {
		return Upload{}, files.WrapError(files.CodeInvalid, op, "", err)
	}
	if request.ExpectedBytes > free || free-request.ExpectedBytes < filesystemReserve {
		return Upload{}, files.NewError(files.CodeDiskFull, op, "", "host filesystem reserve would be exceeded")
	}

	var replaceNode *string
	if request.ConflictMode == ConflictReplace {
		if request.ReplaceNodeID == "" {
			return Upload{}, files.NewError(files.CodeInvalid, op, "", "replace_node_id is required")
		}
		if _, err := files.Authorize(ctx, tx, request.ActorID, request.ReplaceNodeID, files.ActionReplace, now); err != nil {
			return Upload{}, err
		}
		var ownerID, parentID, kind, nameKey string
		var trashed sql.NullString
		if err := tx.QueryRowContext(ctx, "SELECT owner_id, parent_id, kind, name_key, trashed_at FROM nodes WHERE id = ?", request.ReplaceNodeID).Scan(&ownerID, &parentID, &kind, &nameKey, &trashed); err != nil {
			return Upload{}, files.NewError(files.CodeNotFound, op, request.ReplaceNodeID, "replacement target not found")
		}
		if ownerID != access.OwnerID || parentID != request.ParentID || kind != "file" || trashed.Valid || nameKey != key {
			return Upload{}, files.NewError(files.CodeInvalid, op, request.ReplaceNodeID, "replacement target does not match destination and name")
		}
		replaceNode = &request.ReplaceNodeID
	} else {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT 1 WHERE EXISTS (
			SELECT 1 FROM nodes WHERE owner_id = ? AND parent_id = ? AND name_key = ? AND trashed_at IS NULL
		) OR EXISTS (
			SELECT 1 FROM uploads WHERE owner_id = ? AND parent_id = ? AND name_key = ? AND state IN ('pending', 'finalizing')
		)`, access.OwnerID, request.ParentID, key, access.OwnerID, request.ParentID, key).Scan(&exists)
		if err == nil && request.ConflictMode == ConflictFail {
			return Upload{}, files.NewError(files.CodeConflict, op, request.ParentID, "a sibling already has that name")
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return Upload{}, err
		}
		if request.ConflictMode == ConflictKeepBoth && err == nil {
			display, key, err = chooseAvailableName(ctx, tx, access.OwnerID, request.ParentID, display, id)
			if err != nil {
				return Upload{}, err
			}
		}
	}
	request.ShareID = ""
	if !access.Owner && access.Permission == "editor" {
		if !access.AllowEditorUploads {
			return Upload{}, files.NewError(files.CodeForbidden, op, access.ShareID, "editor uploads are disabled")
		}
		if !access.EditorAllowance.Valid {
			return Upload{}, files.NewError(files.CodeInvalidState, op, access.ShareID, "editor upload allowance is missing")
		}
		result, err := tx.ExecContext(ctx, `UPDATE shares SET editor_used_bytes = editor_used_bytes + ?, updated_at = ?
            WHERE id = ? AND editor_used_bytes <= editor_allowance_bytes - ?`, request.ExpectedBytes, timeText(now), access.ShareID, request.ExpectedBytes)
		if err != nil {
			return Upload{}, err
		}
		rows, _ := result.RowsAffected()
		if rows != 1 {
			return Upload{}, files.NewError(files.CodeQuota, op, access.ShareID, "share editor allowance would be exceeded")
		}
		request.ShareID = access.ShareID
	}
	if _, err := tx.ExecContext(ctx, "UPDATE users SET reserved_bytes = reserved_bytes + ?, updated_at = ? WHERE id = ?", request.ExpectedBytes, timeText(now), access.OwnerID); err != nil {
		return Upload{}, err
	}
	var shareID any
	if request.ShareID != "" {
		shareID = request.ShareID
	}
	var replaceID any
	if replaceNode != nil {
		replaceID = *replaceNode
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO uploads
        (id, actor_id, owner_id, parent_id, name, name_key, expected_bytes, committed_bytes,
         reserved_bytes, staging_key, conflict_mode, replace_node_id, share_id, state, expires_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`,
		id, request.ActorID, access.OwnerID, request.ParentID, display, key, request.ExpectedBytes, request.ExpectedBytes,
		id, string(request.ConflictMode), replaceID, shareID, timeText(expires), timeText(now), timeText(now))
	if err != nil {
		return Upload{}, files.WrapError(files.CodeConflict, op, id, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Upload{}, err
	}
	return s.Head(ctx, request.ActorID, id)
}

func chooseAvailableName(ctx context.Context, q database.Queryer, ownerID, parentID, name, excludeUploadID string) (string, string, error) {
	display, _, err := files.NormalizeName(name)
	if err != nil {
		return "", "", err
	}
	stem, extension := splitExtension(display)
	for i := 1; i <= 10_000; i++ {
		candidate := fmt.Sprintf("%s (%d)%s", stem, i, extension)
		candidate, candidateKey, err := files.NormalizeName(candidate)
		if err != nil {
			return "", "", err
		}
		var exists int
		err = q.QueryRowContext(ctx, `SELECT 1 WHERE EXISTS (
			SELECT 1 FROM nodes WHERE owner_id = ? AND parent_id = ? AND name_key = ? AND trashed_at IS NULL
		) OR EXISTS (
			SELECT 1 FROM uploads WHERE owner_id = ? AND parent_id = ? AND name_key = ?
			  AND state IN ('pending', 'finalizing') AND id <> ?
		)`, ownerID, parentID, candidateKey, ownerID, parentID, candidateKey, excludeUploadID).Scan(&exists)
		if errors.Is(err, sql.ErrNoRows) {
			return candidate, candidateKey, nil
		}
		if err != nil {
			return "", "", err
		}
	}
	return "", "", files.NewError(files.CodeConflict, "choose upload name", parentID, "too many sibling conflicts")
}

func splitExtension(name string) (string, string) {
	i := strings.LastIndex(name, ".")
	if i <= 0 || i == len(name)-1 {
		return name, ""
	}
	return name[:i], name[i:]
}

func (s *Service) Head(ctx context.Context, actorID, uploadID string) (Upload, error) {
	upload, err := getUpload(ctx, s.db.Reader(), uploadID)
	if err != nil {
		return Upload{}, err
	}
	if upload.ActorID != actorID && upload.OwnerID != actorID {
		return Upload{}, files.NewError(files.CodeForbidden, "head upload", uploadID, "upload is not accessible")
	}
	return upload, nil
}

func (s *Service) Patch(ctx context.Context, request PatchRequest) (Upload, error) {
	const op = "patch upload"
	if request.Body == nil {
		return Upload{}, files.NewError(files.CodeInvalid, op, request.UploadID, "request body is required")
	}
	if request.ContentLength < 0 {
		return Upload{}, files.NewError(files.CodeInvalid, op, request.UploadID, "content length is required")
	}
	if request.ContentLength > s.maxChunk {
		return Upload{}, files.NewError(files.CodeInvalid, op, request.UploadID, "chunk exceeds server maximum")
	}
	unlock := s.locks.lock(request.UploadID)
	defer unlock()
	upload, err := s.Head(ctx, request.ActorID, request.UploadID)
	if err != nil {
		return Upload{}, err
	}
	if upload.State != StatePending {
		return Upload{}, files.NewError(files.CodeInvalidState, op, upload.ID, "upload is not pending")
	}
	if !s.now().Before(upload.ExpiresAt) {
		_ = s.expireLocked(ctx, upload)
		return Upload{}, files.NewError(files.CodeExpired, op, upload.ID, "upload expired")
	}
	if request.Offset != upload.CommittedBytes {
		return Upload{}, files.NewError(files.CodeOffsetMismatch, op, upload.ID, fmt.Sprintf("expected offset %d", upload.CommittedBytes))
	}
	if request.ContentLength > upload.ExpectedBytes-upload.CommittedBytes {
		return Upload{}, files.NewError(files.CodeInvalid, op, upload.ID, "chunk exceeds declared upload length")
	}
	actualSize, err := s.storage.StagingSize(upload.ID)
	if err != nil {
		return Upload{}, files.WrapError(files.CodeInvalid, op, upload.ID, err)
	}
	if actualSize < upload.CommittedBytes {
		return Upload{}, s.failUpload(ctx, upload, "staging_truncated", errors.New("staging file is shorter than committed offset"))
	}
	if actualSize > upload.CommittedBytes {
		if err := s.storage.TruncateStaging(upload.ID, upload.CommittedBytes); err != nil {
			return Upload{}, files.WrapError(files.CodeInvalid, op, upload.ID, err)
		}
	}
	staging, err := s.storage.OpenStaging(upload.ID)
	if err != nil {
		return Upload{}, files.WrapError(files.CodeInvalid, op, upload.ID, err)
	}
	var hasher hash.Hash
	var writer io.Writer = staging
	if request.ChecksumAlgorithm != "" {
		if request.ChecksumAlgorithm != "sha256" || len(request.Checksum) != sha256.Size {
			_ = staging.Close()
			return Upload{}, files.NewError(files.CodeInvalid, op, upload.ID, "only sha256 checksums are supported")
		}
		hasher = sha256.New()
		writer = io.MultiWriter(staging, hasher)
	}
	written, copyErr := io.CopyN(writer, request.Body, request.ContentLength)
	syncErr := staging.Sync()
	closeErr := staging.Close()
	if copyErr != nil || written != request.ContentLength || syncErr != nil || closeErr != nil {
		_ = s.storage.TruncateStaging(upload.ID, upload.CommittedBytes)
		return Upload{}, files.WrapError(files.CodeInvalid, op, upload.ID, errors.Join(copyErr, syncErr, closeErr))
	}
	if hasher != nil && !equalDigest(hasher.Sum(nil), request.Checksum) {
		_ = s.storage.TruncateStaging(upload.ID, upload.CommittedBytes)
		return Upload{}, files.NewError(files.CodeChecksumMismatch, op, upload.ID, "chunk checksum does not match")
	}
	newOffset := upload.CommittedBytes + written
	result, err := s.db.Writer().ExecContext(ctx, `UPDATE uploads SET committed_bytes = ?, updated_at = ?
        WHERE id = ? AND state = 'pending' AND committed_bytes = ?`, newOffset, timeText(s.now()), upload.ID, upload.CommittedBytes)
	if err != nil {
		_ = s.storage.TruncateStaging(upload.ID, upload.CommittedBytes)
		return Upload{}, files.WrapError(files.CodeInvalid, op, upload.ID, err)
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		_ = s.storage.TruncateStaging(upload.ID, upload.CommittedBytes)
		return Upload{}, files.NewError(files.CodeOffsetMismatch, op, upload.ID, "offset changed concurrently")
	}
	if newOffset == upload.ExpectedBytes {
		return s.finalizeLocked(ctx, upload.ID)
	}
	return s.Head(ctx, request.ActorID, upload.ID)
}

// Complete finalizes a fully uploaded resource. HTTP integrations use it for
// zero-byte uploads immediately after creation; it is also safe to retry.
func (s *Service) Complete(ctx context.Context, actorID, uploadID string) (Upload, error) {
	unlock := s.locks.lock(uploadID)
	defer unlock()
	upload, err := s.Head(ctx, actorID, uploadID)
	if err != nil {
		return Upload{}, err
	}
	if upload.State == StateCompleted {
		return upload, nil
	}
	if upload.CommittedBytes != upload.ExpectedBytes {
		return Upload{}, files.NewError(files.CodeInvalidState, "complete upload", uploadID, "upload is incomplete")
	}
	if upload.State == StatePending {
		staging, err := s.storage.OpenStaging(uploadID)
		if err != nil {
			return Upload{}, files.WrapError(files.CodeInvalid, "complete upload", uploadID, err)
		}
		if err := errors.Join(staging.Sync(), staging.Close()); err != nil {
			return Upload{}, files.WrapError(files.CodeInvalid, "complete upload", uploadID, err)
		}
	}
	return s.finalizeLocked(ctx, uploadID)
}

func equalDigest(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for i := range left {
		difference |= left[i] ^ right[i]
	}
	return difference == 0
}

func ParseChecksum(header string) (Checksum, error) {
	if header == "" {
		return Checksum{}, nil
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "sha256" {
		return Checksum{}, files.NewError(files.CodeInvalid, "parse upload checksum", "", "expected sha256 checksum")
	}
	digest, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(digest) != sha256.Size {
		return Checksum{}, files.NewError(files.CodeInvalid, "parse upload checksum", "", "invalid sha256 digest")
	}
	return Checksum{Algorithm: "sha256", Digest: digest}, nil
}

func (s *Service) Cancel(ctx context.Context, actorID, uploadID string) error {
	unlock := s.locks.lock(uploadID)
	defer unlock()
	upload, err := s.Head(ctx, actorID, uploadID)
	if err != nil {
		return err
	}
	if upload.State == StateCancelled {
		return nil
	}
	if upload.State != StatePending {
		return files.NewError(files.CodeInvalidState, "cancel upload", uploadID, "upload cannot be cancelled")
	}
	if err := s.releaseReservation(ctx, upload, StateCancelled, ""); err != nil {
		return err
	}
	return s.storage.RemoveStaging(uploadID)
}

func (s *Service) expireLocked(ctx context.Context, upload Upload) error {
	if upload.State != StatePending {
		return nil
	}
	if err := s.releaseReservation(ctx, upload, StateExpired, "expired"); err != nil {
		return err
	}
	return s.storage.RemoveStaging(upload.ID)
}

func (s *Service) releaseReservation(ctx context.Context, upload Upload, state State, errorCode string) error {
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var errorValue any
	if errorCode != "" {
		errorValue = errorCode
	}
	result, err := tx.ExecContext(ctx, `UPDATE uploads SET state = ?, error_code = ?, reserved_bytes = 0, updated_at = ?
		WHERE id = ? AND state IN ('pending', 'finalizing')`, string(state), errorValue, timeText(s.now()), upload.ID)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return nil
	}
	quotaResult, err := tx.ExecContext(ctx, `UPDATE users SET reserved_bytes = reserved_bytes - ?,
		updated_at = ? WHERE id = ? AND reserved_bytes >= ?`, upload.ReservedBytes, timeText(s.now()), upload.OwnerID, upload.ReservedBytes)
	if err != nil {
		return err
	}
	quotaRows, _ := quotaResult.RowsAffected()
	if quotaRows != 1 {
		return files.NewError(files.CodeInvalidState, "release upload reservation", upload.OwnerID, "quota reservation is inconsistent")
	}
	if upload.ShareID != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE shares SET editor_used_bytes = CASE WHEN editor_used_bytes >= ? THEN editor_used_bytes - ? ELSE 0 END,
            updated_at = ? WHERE id = ?`, upload.ReservedBytes, upload.ReservedBytes, timeText(s.now()), *upload.ShareID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Service) failUpload(ctx context.Context, upload Upload, code string, cause error) error {
	if err := s.releaseReservation(ctx, upload, StateFailed, code); err != nil {
		return errors.Join(cause, err)
	}
	return files.WrapError(files.CodeInvalidState, "fail upload", upload.ID, cause)
}

func timeText(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
