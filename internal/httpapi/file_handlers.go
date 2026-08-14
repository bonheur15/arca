package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"arca/internal/auth"
	"arca/internal/files"
	"arca/internal/preview"
	"arca/internal/uploads"

	"github.com/go-chi/chi/v5"
)

func (s *Server) checkScope(w http.ResponseWriter, r *http.Request, scope string) bool {
	p := principal(r)
	if p.CookieAuth || p.HasScope(scope) {
		return true
	}
	WriteProblem(w, r, http.StatusForbidden, "insufficient_scope", "Insufficient token scope", "This personal access token does not grant "+scope+".")
	return false
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeFilesRead)) {
		return
	}
	p := principal(r)
	parentID := strings.TrimSpace(r.URL.Query().Get("parent_id"))
	if parentID == "" {
		user, err := s.runtime.AccountRepo.GetUserByID(r.Context(), p.UserID)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		parentID = user.RootNodeID
	}
	page, err := s.runtime.Files.List(r.Context(), p.UserID, parentID, files.ListOptions{Limit: queryLimit(r), Cursor: r.URL.Query().Get("cursor")})
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": page.Items, "next_cursor": page.NextCursor, "breadcrumbs": s.breadcrumbs(r, p.UserID, parentID)})
}

func (s *Server) breadcrumbs(r *http.Request, actorID, nodeID string) []map[string]any {
	rows, err := s.runtime.Database.Reader().QueryContext(r.Context(), `WITH RECURSIVE ancestors(id, parent_id, name, depth) AS (
		SELECT id, parent_id, name, 0 FROM nodes WHERE id = ?
		UNION ALL SELECT n.id, n.parent_id, n.name, a.depth + 1 FROM nodes n JOIN ancestors a ON a.parent_id = n.id WHERE a.depth < 100
	) SELECT id, name FROM ancestors ORDER BY depth DESC`, nodeID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	result := make([]map[string]any, 0)
	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) != nil {
			return result
		}
		if name == "" {
			name = "Files"
		}
		result = append(result, map[string]any{"id": id, "name": name})
	}
	return result
}

func (s *Server) getNode(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeFilesRead)) {
		return
	}
	node, err := s.runtime.Files.Get(r.Context(), principal(r).UserID, chi.URLParam(r, "nodeID"))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, node.Revision))
	WriteJSON(w, http.StatusOK, node)
}

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeFilesWrite)) {
		return
	}
	var body struct {
		ParentID    string `json:"parentId"`
		ParentIDAlt string `json:"parent_id"`
		Name        string `json:"name"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	if body.ParentID == "" {
		body.ParentID = body.ParentIDAlt
	}
	p := principal(r)
	if body.ParentID == "" {
		user, err := s.runtime.AccountRepo.GetUserByID(r.Context(), p.UserID)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		body.ParentID = user.RootNodeID
	}
	node, err := s.runtime.Files.CreateFolder(r.Context(), p.UserID, body.ParentID, body.Name)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, node.Revision))
	w.Header().Set("Location", "/api/v1/nodes/"+node.ID)
	WriteJSON(w, http.StatusCreated, node)
}

func (s *Server) renameNode(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeFilesWrite)) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	revision, err := revisionFromRequest(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	node, err := s.runtime.Files.Rename(r.Context(), principal(r).UserID, chi.URLParam(r, "nodeID"), body.Name, revision)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, node.Revision))
	WriteJSON(w, http.StatusOK, node)
}

func (s *Server) moveNode(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeFilesWrite)) {
		return
	}
	var body struct {
		ParentID    string `json:"parentId"`
		ParentIDAlt string `json:"parent_id"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	if body.ParentID == "" {
		body.ParentID = body.ParentIDAlt
	}
	if body.ParentID == "" {
		user, err := s.runtime.AccountRepo.GetUserByID(r.Context(), principal(r).UserID)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		body.ParentID = user.RootNodeID
	}
	revision, err := revisionFromRequest(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	node, err := s.runtime.Files.Move(r.Context(), principal(r).UserID, chi.URLParam(r, "nodeID"), body.ParentID, revision)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, node)
}

func (s *Server) trashNode(w http.ResponseWriter, r *http.Request) {
	s.nodeRevisionAction(w, r, s.runtime.Files.Trash)
}

func (s *Server) restoreNode(w http.ResponseWriter, r *http.Request) {
	s.nodeRevisionAction(w, r, s.runtime.Files.Restore)
}

func (s *Server) nodeRevisionAction(w http.ResponseWriter, r *http.Request, action func(context.Context, string, string, int64) (files.Node, error)) {
	if !s.checkScope(w, r, string(auth.ScopeFilesWrite)) {
		return
	}
	revision, err := revisionFromRequest(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	node, err := action(r.Context(), principal(r).UserID, chi.URLParam(r, "nodeID"), revision)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, node)
}

func (s *Server) purgeNode(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeFilesWrite)) {
		return
	}
	revision, err := revisionFromRequest(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	result, err := s.runtime.Files.Purge(r.Context(), principal(r).UserID, chi.URLParam(r, "nodeID"), revision)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

func (s *Server) trash(w http.ResponseWriter, r *http.Request) {
	page, err := s.runtime.Files.ListTrash(r.Context(), principal(r).UserID, files.ListOptions{Limit: queryLimit(r), Cursor: r.URL.Query().Get("cursor")})
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, page)
}

func (s *Server) recent(w http.ResponseWriter, r *http.Request) {
	page, err := s.runtime.Files.Recent(r.Context(), principal(r).UserID, files.ListOptions{Limit: queryLimit(r), Cursor: r.URL.Query().Get("cursor")})
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, page)
}

func (s *Server) favorites(w http.ResponseWriter, r *http.Request) {
	page, err := s.runtime.Files.ListFavorites(r.Context(), principal(r).UserID, files.ListOptions{Limit: queryLimit(r), Cursor: r.URL.Query().Get("cursor")})
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, page)
}

func (s *Server) favorite(w http.ResponseWriter, r *http.Request)   { s.setFavorite(w, r, true) }
func (s *Server) unfavorite(w http.ResponseWriter, r *http.Request) { s.setFavorite(w, r, false) }
func (s *Server) setFavorite(w http.ResponseWriter, r *http.Request, value bool) {
	if err := s.runtime.Files.SetFavorite(r.Context(), principal(r).UserID, chi.URLParam(r, "nodeID"), value); err != nil {
		s.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	page, err := s.runtime.Files.Search(r.Context(), principal(r).UserID, files.SearchOptions{Query: r.URL.Query().Get("q"), Kind: files.Kind(r.URL.Query().Get("kind")), MIMEType: r.URL.Query().Get("mime_type"), Limit: queryLimit(r), Cursor: r.URL.Query().Get("cursor")})
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, page)
}

func (s *Server) versions(w http.ResponseWriter, r *http.Request) {
	items, err := s.runtime.Files.ListVersions(r.Context(), principal(r).UserID, chi.URLParam(r, "nodeID"))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) restoreVersion(w http.ResponseWriter, r *http.Request) {
	revision, err := revisionFromRequest(r)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	version, err := s.runtime.Files.RestoreVersion(r.Context(), principal(r).UserID, chi.URLParam(r, "nodeID"), chi.URLParam(r, "versionID"), revision)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusCreated, version)
}

func (s *Server) content(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeFilesRead)) {
		return
	}
	resolved, err := s.runtime.Files.Content(r.Context(), principal(r).UserID, chi.URLParam(r, "nodeID"), r.URL.Query().Get("version_id"))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	s.serveResolvedContent(w, r, resolved, func() error {
		_, err := s.runtime.Files.Content(r.Context(), principal(r).UserID, resolved.Node.ID, resolved.Version.ID)
		return err
	})
}

func (s *Server) serveResolvedContent(w http.ResponseWriter, r *http.Request, resolved files.Content, reauthorize func() error) {
	if strings.Contains(r.Header.Get("Range"), ",") {
		WriteProblem(w, r, http.StatusRequestedRangeNotSatisfiable, "range_not_satisfiable", "Unsupported range", "Arca accepts one byte range per request.")
		return
	}
	reader, err := s.runtime.Storage.OpenBlob(resolved.StorageKey)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	defer reader.Close()
	seeker, ok := reader.(io.ReadSeeker)
	if !ok {
		s.handleError(w, r, errors.New("blob storage does not provide seekable content"))
		return
	}
	if err := reauthorize(); err != nil {
		s.handleError(w, r, err)
		return
	}
	decision := preview.Decide(resolved.Node.Name, resolved.Version.MIMEType)
	inline := r.URL.Query().Get("preview") == "1" && decision.Inline && preview.ValidatePreviewSize(decision, resolved.Version.SizeBytes) == nil
	disposition := "attachment"
	contentType := resolved.Version.MIMEType
	if inline {
		disposition = "inline"
		contentType = decision.ContentType
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": resolved.Node.Name}))
	w.Header().Set("ETag", `"`+resolved.Version.SHA256+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Accept-Ranges", "bytes")
	http.ServeContent(w, r, resolved.Node.Name, resolved.Version.CreatedAt, seeker)
}

func (s *Server) createUpload(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeFilesWrite)) {
		return
	}
	expected, err := strconv.ParseInt(r.Header.Get("Upload-Length"), 10, 64)
	if err != nil || expected < 0 {
		WriteProblem(w, r, http.StatusBadRequest, "upload_length_required", "Upload length required", "Provide a non-negative Upload-Length.")
		return
	}
	metadata, err := parseUploadMetadata(r.Header.Get("Upload-Metadata"))
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_upload_metadata", "Invalid upload metadata", err.Error())
		return
	}
	p := principal(r)
	parentID := metadata["parent_id"]
	if parentID == "" {
		user, getErr := s.runtime.AccountRepo.GetUserByID(r.Context(), p.UserID)
		if getErr != nil {
			s.handleError(w, r, getErr)
			return
		}
		parentID = user.RootNodeID
	}
	upload, err := s.runtime.Uploads.Create(r.Context(), uploads.CreateRequest{ActorID: p.UserID, ParentID: parentID, Name: metadata["filename"], ExpectedBytes: expected, ConflictMode: uploads.ConflictMode(metadata["conflict"]), ReplaceNodeID: metadata["replace_node_id"], ShareID: metadata["share_id"]})
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	if expected == 0 {
		upload, err = s.runtime.Uploads.Complete(r.Context(), p.UserID, upload.ID)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
	}
	w.Header().Set("Location", "/api/v1/uploads/"+upload.ID)
	w.Header().Set("Upload-Offset", strconv.FormatInt(upload.CommittedBytes, 10))
	w.Header().Set("Upload-Expires", upload.ExpiresAt.Format(http.TimeFormat))
	WriteJSON(w, http.StatusCreated, upload)
}

func (s *Server) headUpload(w http.ResponseWriter, r *http.Request) {
	upload, err := s.runtime.Uploads.Head(r.Context(), principal(r).UserID, chi.URLParam(r, "uploadID"))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	w.Header().Set("Upload-Length", strconv.FormatInt(upload.ExpectedBytes, 10))
	w.Header().Set("Upload-Offset", strconv.FormatInt(upload.CommittedBytes, 10))
	w.Header().Set("Upload-Expires", upload.ExpiresAt.Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) patchUpload(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeFilesWrite)) {
		return
	}
	if r.Header.Get("Content-Type") != "application/offset+octet-stream" {
		WriteProblem(w, r, http.StatusUnsupportedMediaType, "invalid_upload_content_type", "Invalid upload content type", "Tus PATCH requests use application/offset+octet-stream.")
		return
	}
	offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || offset < 0 || r.ContentLength < 0 {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_upload_offset", "Invalid upload offset", "Provide valid Upload-Offset and Content-Length headers.")
		return
	}
	checksum, err := uploads.ParseChecksum(r.Header.Get("Upload-Checksum"))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	upload, err := s.runtime.Uploads.Patch(r.Context(), uploads.PatchRequest{ActorID: principal(r).UserID, UploadID: chi.URLParam(r, "uploadID"), Offset: offset, ContentLength: r.ContentLength, Body: r.Body, ChecksumAlgorithm: checksum.Algorithm, Checksum: checksum.Digest})
	if err != nil {
		if files.ErrorCodeOf(err) == files.CodeOffsetMismatch {
			if current, headErr := s.runtime.Uploads.Head(r.Context(), principal(r).UserID, chi.URLParam(r, "uploadID")); headErr == nil {
				w.Header().Set("Upload-Offset", strconv.FormatInt(current.CommittedBytes, 10))
			}
		}
		s.handleError(w, r, err)
		return
	}
	w.Header().Set("Upload-Offset", strconv.FormatInt(upload.CommittedBytes, 10))
	w.Header().Set("Upload-Expires", upload.ExpiresAt.Format(http.TimeFormat))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) cancelUpload(w http.ResponseWriter, r *http.Request) {
	if err := s.runtime.Uploads.Cancel(r.Context(), principal(r).UserID, chi.URLParam(r, "uploadID")); err != nil {
		s.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseUploadMetadata(value string) (map[string]string, error) {
	if len(value) > uploads.MaxMetadataLength {
		return nil, errors.New("upload metadata is too large")
	}
	result := make(map[string]string)
	if strings.TrimSpace(value) == "" {
		return result, nil
	}
	for _, pair := range strings.Split(value, ",") {
		parts := strings.Fields(strings.TrimSpace(pair))
		if len(parts) != 2 || parts[0] == "" {
			return nil, errors.New("metadata entries must contain a key and base64 value")
		}
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil || strings.ContainsRune(string(decoded), 0) {
			return nil, errors.New("metadata contains an invalid base64 value")
		}
		result[parts[0]] = string(decoded)
	}
	return result, nil
}

func queryLimit(r *http.Request) int {
	value, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if value <= 0 {
		return 50
	}
	if value > 200 {
		return 200
	}
	return value
}
