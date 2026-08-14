package httpapi

import (
	"archive/zip"
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"

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
	all, _, err := s.publicNodes(r, session.ShareID, roots)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	nodes := make(map[string]files.Node, len(all))
	for _, node := range all {
		nodes[node.ID] = node
	}
	entries, err := s.preparePublicArchive(r, roots, nodes)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	// Revalidate the public session immediately before committing response
	// headers; later file iterations revalidate each node again.
	active, err := s.runtime.Shares.ResolvePublicSession(r.Context(), publicCookieValue(s, r))
	if err != nil || active.ShareID != session.ShareID {
		s.genericPublicFailure(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": "arca-shared.zip"}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	archive := zip.NewWriter(w)
	buffer := make([]byte, archiveCopyBuffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.ArchivePath, Method: zip.Store, Modified: entry.Node.UpdatedAt.UTC()}
		if entry.Node.Kind == files.KindFolder {
			header.Name = strings.TrimSuffix(header.Name, "/") + "/"
			header.SetMode(0o755 | 0o040000)
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
		active, activeErr := s.runtime.Shares.ResolvePublicSession(r.Context(), publicCookieValue(s, r))
		allowed, allowedErr := s.runtime.Shares.CanAccessPublicNode(r.Context(), session.ShareID, entry.Node.ID)
		if activeErr != nil || active.ShareID != session.ShareID || allowedErr != nil || !allowed {
			s.logger.Warn("public archive permission changed during stream", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID)
			return
		}
		reader, err := s.runtime.Storage.OpenBlob(resolved.StorageKey)
		if err != nil {
			s.logger.Error("public archive blob open failed", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID, "error", err)
			return
		}
		header.UncompressedSize64 = uint64(resolved.Version.SizeBytes)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			_ = reader.Close()
			s.logger.Error("public archive file header failed", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID, "error", err)
			return
		}
		rateReader := newByteRateReader(r.Context(), reader, s.downloadRate(r.Context(), entry.Node.OwnerID))
		copied, copyErr := io.CopyBuffer(writer, io.LimitReader(rateReader, resolved.Version.SizeBytes+1), buffer)
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

func (s *Server) preparePublicArchive(r *http.Request, roots []string, visible map[string]files.Node) ([]archiveEntry, error) {
	usedPaths := make(map[string]struct{})
	entries := make([]archiveEntry, 0, len(visible))
	for _, rootID := range roots {
		root, ok := visible[rootID]
		if !ok {
			return nil, shares.ErrPublicUnavailable
		}
		tree, err := collectArchiveTree(r.Context(), s.runtime.Database.Reader(), rootID)
		if err != nil {
			return nil, err
		}
		paths := make(map[string]string, len(tree))
		for _, raw := range tree {
			node, ok := visible[raw.ID]
			if !ok {
				continue
			}
			parentPath := ""
			if raw.ID != rootID && raw.ParentID.Valid {
				parentPath, ok = paths[raw.ParentID.String]
				if !ok {
					return nil, shares.ErrPublicUnavailable
				}
			}
			name := safeArchiveSegment(node.Name)
			if node.ID == root.ID && node.Name == "" {
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
			entries = append(entries, archiveEntry{Node: node, ArchivePath: archivePath})
			if len(entries) > maxArchiveEntries {
				return nil, files.NewError(files.CodeItemLimit, "create public archive", "", "archive would exceed 100000 entries")
			}
		}
	}
	return entries, nil
}
