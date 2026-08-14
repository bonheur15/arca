package httpapi

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"arca/internal/files"
	"arca/internal/shares"
)

func (s *Server) publicArchive(w http.ResponseWriter, r *http.Request) {
	session, err := s.publicSession(r)
	if err != nil {
		s.genericPublicFailure(w, r)
		return
	}
	roots, err := s.runtime.Shares.PublicRoots(r.Context(), session.ShareID)
	if err != nil {
		s.genericPublicFailure(w, r)
		return
	}
	entries, err := s.preparePublicArchive(r, session.ShareID, roots)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	// Revalidate the public session immediately before committing response
	// headers; later entry iterations revalidate each node again.
	active, err := s.runtime.Shares.ResolvePublicSession(r.Context(), publicCookieValue(s, r))
	if err != nil || active.ShareID != session.ShareID {
		s.genericPublicFailure(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "arca-shared.zip"}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Accept-Ranges", "none")
	archive := zip.NewWriter(w)
	buffer := make([]byte, archiveCopyBuffer)
	downloadRates := make(map[string]int64)
	publicToken := publicCookieValue(s, r)
	for _, entry := range entries {
		if err := r.Context().Err(); err != nil {
			return
		}
		header := &zip.FileHeader{Name: entry.ArchivePath, Method: zip.Store, Modified: entry.Node.UpdatedAt.UTC()}
		if entry.Node.Kind == files.KindFolder {
			if !s.publicArchiveEntryAllowed(r.Context(), publicToken, session.ShareID, entry.Node.ID) {
				s.logger.Warn("public archive permission changed during stream", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID)
				return
			}
			header.Name = strings.TrimSuffix(header.Name, "/") + "/"
			header.SetMode(os.ModeDir | 0o755)
			if _, err := archive.CreateHeader(header); err != nil {
				s.logger.Error("public archive folder header failed", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID, "error", err)
				return
			}
			continue
		}
		resolved, err := s.resolvePublicContent(r, entry.Node.ID)
		if err != nil {
			s.logger.Warn("public archive content changed during stream", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID, "error", err)
			return
		}
		reader, err := s.runtime.Storage.OpenBlob(resolved.StorageKey)
		if err != nil {
			s.logger.Error("public archive blob open failed", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID, "error", err)
			return
		}
		if !s.publicArchiveEntryAllowed(r.Context(), publicToken, session.ShareID, entry.Node.ID) {
			_ = reader.Close()
			s.logger.Warn("public archive permission changed during stream", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID)
			return
		}
		header.UncompressedSize64 = uint64(resolved.Version.SizeBytes)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			_ = reader.Close()
			s.logger.Error("public archive file header failed", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID, "error", err)
			return
		}
		limited := io.LimitReader(reader, resolved.Version.SizeBytes)
		rate, ok := downloadRates[entry.Node.OwnerID]
		if !ok {
			rate = s.downloadRate(r.Context(), entry.Node.OwnerID)
			downloadRates[entry.Node.OwnerID] = rate
		}
		rateReader := newByteRateReader(r.Context(), limited, rate)
		copied, copyErr := io.CopyBuffer(writer, rateReader, buffer)
		closeErr := reader.Close()
		if copyErr != nil || closeErr != nil || copied != resolved.Version.SizeBytes {
			s.logger.Error("public archive file stream failed", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID,
				"copied", copied, "expected", resolved.Version.SizeBytes, "error", errors.Join(copyErr, closeErr))
			return
		}
	}
	if err := archive.Close(); err != nil {
		s.logger.Error("public archive finalize failed", "request_id", RequestID(r.Context()), "error", err)
	}
}

func (s *Server) publicArchiveEntryAllowed(ctx context.Context, token, shareID, nodeID string) bool {
	if token == "" || shareID == "" || nodeID == "" {
		return false
	}
	tokenHash := sha256.Sum256([]byte(token))
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var count int
	err := s.runtime.Database.Reader().QueryRowContext(ctx, `WITH RECURSIVE ancestors(id, parent_id, trashed_at, depth) AS (
		SELECT id, parent_id, trashed_at, 0 FROM nodes WHERE id = ?
		UNION ALL SELECT n.id, n.parent_id, n.trashed_at, ancestors.depth + 1
		FROM nodes n JOIN ancestors ON n.id = ancestors.parent_id WHERE ancestors.depth < 100
	) SELECT COUNT(*)
	FROM public_access_sessions session
	JOIN public_shares share ON share.id = session.public_share_id
	JOIN public_share_roots root ON root.public_share_id = share.id
	JOIN ancestors ON ancestors.id = root.node_id
	WHERE session.token_hash = ? AND share.id = ?
		AND session.expires_at > ? AND share.expires_at > ? AND share.revoked_at IS NULL
		AND NOT EXISTS (SELECT 1 FROM ancestors dirty WHERE dirty.trashed_at IS NOT NULL)`,
		nodeID, tokenHash[:], shareID, now, now).Scan(&count)
	return err == nil && count > 0
}

func (s *Server) preparePublicArchive(r *http.Request, shareID string, roots []string) ([]archiveEntry, error) {
	usedPaths := make(map[string]struct{})
	entries := make([]archiveEntry, 0, min(len(roots), maxArchiveEntries))
	for _, rootID := range roots {
		remaining := maxArchiveEntries - len(entries)
		if remaining <= 0 {
			return nil, files.NewError(files.CodeItemLimit, "create public archive", "", "archive would exceed 100000 entries")
		}
		tree, err := collectPublicArchiveTree(r.Context(), s.runtime.Database.Reader(), shareID, rootID, remaining+1)
		if err != nil {
			return nil, err
		}
		if len(tree) == 0 {
			return nil, shares.ErrPublicUnavailable
		}
		if len(tree) > remaining {
			return nil, files.NewError(files.CodeItemLimit, "create public archive", "", "archive would exceed 100000 entries")
		}
		paths := make(map[string]string, len(tree))
		for _, node := range tree {
			parentPath := ""
			if node.ID != rootID && node.ParentID != nil {
				var ok bool
				parentPath, ok = paths[*node.ParentID]
				if !ok {
					return nil, shares.ErrPublicUnavailable
				}
			}
			name := safeArchiveSegment(node.Name)
			if node.ID == rootID && node.Name == "" {
				name = "Shared files"
			}
			candidate := name
			if parentPath != "" {
				candidate = path.Join(strings.TrimSuffix(parentPath, "/"), name)
			}
			archivePath, err := uniqueArchivePath(candidate, node.Kind == files.KindFolder, usedPaths)
			if err != nil {
				return nil, err
			}
			paths[node.ID] = archivePath
			if node.Kind == files.KindFile {
				if _, err := s.resolvePublicContent(r, node.ID); err != nil {
					return nil, err
				}
			}
			entries = append(entries, archiveEntry{Node: node, ArchivePath: archivePath})
		}
	}
	return entries, nil
}

func collectPublicArchiveTree(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, shareID, rootID string, limit int) ([]files.Node, error) {
	rows, err := q.QueryContext(ctx, `WITH RECURSIVE tree(
		id, owner_id, parent_id, kind, name, mime_type, size_bytes, current_version_id,
		revision, created_by, trashed_at, original_parent_id, created_at, updated_at, depth, name_key
	) AS (
		SELECT n.id, n.owner_id, n.parent_id, n.kind, n.name, n.mime_type, n.size_bytes, n.current_version_id,
			n.revision, n.created_by, n.trashed_at, n.original_parent_id, n.created_at, n.updated_at, 0, n.name_key
		FROM public_share_roots root JOIN nodes n ON n.id = root.node_id
		WHERE root.public_share_id = ? AND root.node_id = ? AND n.trashed_at IS NULL
		UNION ALL
		SELECT n.id, n.owner_id, n.parent_id, n.kind, n.name, n.mime_type, n.size_bytes, n.current_version_id,
			n.revision, n.created_by, n.trashed_at, n.original_parent_id, n.created_at, n.updated_at, tree.depth + 1, n.name_key
		FROM nodes n JOIN tree ON n.parent_id = tree.id
		WHERE n.trashed_at IS NULL AND tree.depth < 100
	) SELECT id, owner_id, parent_id, kind, name, mime_type, size_bytes, current_version_id,
		revision, created_by, trashed_at, original_parent_id, created_at, updated_at
	FROM tree ORDER BY depth, name_key, id LIMIT ?`, shareID, rootID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]files.Node, 0, min(limit, 1024))
	for rows.Next() {
		node, err := scanPublicNode(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, node)
	}
	return result, rows.Err()
}
