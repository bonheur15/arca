package uploads

import (
	"context"
	"database/sql"
	"errors"
	"io"

	"arca/internal/files"
)

type SaveCopyRequest struct {
	ActorID       string
	SourceNodeID  string
	DestinationID string
	Name          string
	ConflictMode  ConflictMode
}

// SaveCopy streams an accessible file into a new destination-owned blob. It is
// the safe path for saving a shared file across owners; filenames never become
// storage paths and destination quota is reserved before bytes are copied.
func (s *Service) SaveCopy(ctx context.Context, request SaveCopyRequest) (Upload, error) {
	const op = "save file copy"
	if _, err := files.Authorize(ctx, s.db.Reader(), request.ActorID, request.SourceNodeID, files.ActionRead, s.now()); err != nil {
		return Upload{}, err
	}
	var sourceName, kind, storageKey, blobState string
	var size int64
	err := s.db.Reader().QueryRowContext(ctx, `SELECT n.name, n.kind, v.size_bytes, b.storage_key, b.state
		FROM nodes n
		JOIN file_versions v ON v.id = n.current_version_id
		JOIN blobs b ON b.id = v.blob_id
		WHERE n.id = ? AND n.trashed_at IS NULL`, request.SourceNodeID).Scan(
		&sourceName, &kind, &size, &storageKey, &blobState)
	if errors.Is(err, sql.ErrNoRows) {
		return Upload{}, files.NewError(files.CodeNotFound, op, request.SourceNodeID, "source file is unavailable")
	}
	if err != nil {
		return Upload{}, files.WrapError(files.CodeInvalid, op, request.SourceNodeID, err)
	}
	if kind != string(files.KindFile) || blobState != "ready" {
		return Upload{}, files.NewError(files.CodeInvalidState, op, request.SourceNodeID, "source is not a ready file")
	}
	name := request.Name
	if name == "" {
		name = sourceName
	}
	mode := request.ConflictMode
	if mode == "" {
		mode = ConflictKeepBoth
	}
	upload, err := s.Create(ctx, CreateRequest{
		ActorID: request.ActorID, ParentID: request.DestinationID, Name: name,
		ExpectedBytes: size, ConflictMode: mode,
	})
	if err != nil {
		return Upload{}, err
	}
	reader, err := s.storage.OpenBlob(storageKey)
	if err != nil {
		return Upload{}, errors.Join(files.WrapError(files.CodeInvalid, op, request.SourceNodeID, err), s.Cancel(context.Background(), request.ActorID, upload.ID))
	}
	defer reader.Close()
	if size == 0 {
		completed, completeErr := s.Complete(ctx, request.ActorID, upload.ID)
		if completeErr != nil {
			return Upload{}, errors.Join(completeErr, s.Cancel(context.Background(), request.ActorID, upload.ID))
		}
		return completed, nil
	}
	remaining := size
	for remaining > 0 {
		chunk := min(remaining, s.maxChunk)
		limited := &io.LimitedReader{R: reader, N: chunk}
		upload, err = s.Patch(ctx, PatchRequest{
			ActorID: request.ActorID, UploadID: upload.ID, Offset: upload.CommittedBytes,
			ContentLength: chunk, Body: limited,
		})
		if err != nil {
			return Upload{}, errors.Join(err, s.Cancel(context.Background(), request.ActorID, upload.ID))
		}
		if limited.N != 0 {
			return Upload{}, errors.Join(
				files.NewError(files.CodeInvalidState, op, request.SourceNodeID, "source blob ended before its recorded size"),
				s.Cancel(context.Background(), request.ActorID, upload.ID),
			)
		}
		remaining -= chunk
	}
	if upload.State != StateCompleted {
		return Upload{}, files.NewError(files.CodeInvalidState, op, upload.ID, "copy did not finalize")
	}
	return upload, nil
}
