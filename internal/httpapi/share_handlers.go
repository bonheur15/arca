package httpapi

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"arca/internal/auth"
	"arca/internal/files"
	"arca/internal/shares"

	"github.com/go-chi/chi/v5"
)

const publicCookieName = "__Host-arca_public"

func (s *Server) createShare(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeSharesWrite)) {
		return
	}
	var body struct {
		RootIDs              []string `json:"rootIds"`
		RootIDsAlt           []string `json:"root_ids"`
		Recipients           []string `json:"recipients"`
		RecipientIDs         []string `json:"recipientIds"`
		Permission           string   `json:"permission"`
		ExpiresAt            string   `json:"expiresAt"`
		AllowEditorUploads   bool     `json:"allowEditorUploads"`
		EditorAllowanceBytes *int64   `json:"editorAllowanceBytes"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	if len(body.RootIDs) == 0 {
		body.RootIDs = body.RootIDsAlt
	}
	recipientIDs := append([]string(nil), body.RecipientIDs...)
	for _, candidate := range body.Recipients {
		user, err := s.runtime.AccountRepo.GetUserByUsernameOrEmail(r.Context(), candidate)
		if err != nil || !user.State.CanAuthenticate() {
			WriteProblem(w, r, http.StatusBadRequest, "unknown_recipient", "Unknown recipient", "Every recipient must be an active user on this Arca instance.")
			return
		}
		recipientIDs = append(recipientIDs, user.ID)
	}
	expiresAt, err := parseTimePointer(body.ExpiresAt)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_expiry", "Invalid expiration", "expiresAt must be an RFC3339 timestamp.")
		return
	}
	created, err := s.runtime.Shares.CreateInternal(r.Context(), shares.CreateInternalInput{OwnerID: principal(r).UserID, RootIDs: body.RootIDs, RecipientIDs: recipientIDs, Permission: shares.Permission(body.Permission), ExpiresAt: expiresAt, AllowEditorUploads: body.AllowEditorUploads, EditorAllowanceBytes: body.EditorAllowanceBytes})
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	if err := s.recordRequestAudit(r, "share.created", "share", created.ID, map[string]any{
		"root_ids": created.RootIDs, "recipient_ids": created.RecipientIDs, "permission": created.Permission,
	}); err != nil {
		_ = s.runtime.Shares.RevokeInternal(r.Context(), principal(r).UserID, created.ID, false)
		s.handleError(w, r, err)
		return
	}
	for _, recipientID := range created.RecipientIDs {
		s.events.Publish(recipientID, Event{ID: randomID(8), Type: "share", Data: map[string]any{"share_id": created.ID, "action": "created"}})
		s.events.Publish(recipientID, Event{ID: randomID(8), Type: "notification", Data: map[string]any{"kind": "share.created"}})
	}
	WriteJSON(w, http.StatusCreated, s.hydrateInternalShare(r, created))
}

func (s *Server) listShares(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeSharesRead)) {
		return
	}
	p := principal(r)
	rows, err := s.runtime.Database.Reader().QueryContext(r.Context(), `SELECT id, owner_id, permission, allow_editor_uploads,
		editor_allowance_bytes, editor_used_bytes, expires_at, created_at, updated_at
		FROM shares WHERE (owner_id = ? OR EXISTS (SELECT 1 FROM share_recipients sr WHERE sr.share_id = shares.id AND sr.user_id = ?))
		AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 200`, p.UserID, p.UserID)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	defer rows.Close()
	items := make([]any, 0)
	for rows.Next() {
		var item shares.InternalShare
		var allowance sql.NullInt64
		var expires sql.NullString
		var created, updated string
		if err := rows.Scan(&item.ID, &item.OwnerID, &item.Permission, &item.AllowEditorUploads, &allowance, &item.EditorUsedBytes, &expires, &created, &updated); err != nil {
			s.handleError(w, r, err)
			return
		}
		if allowance.Valid {
			value := allowance.Int64
			item.EditorAllowanceBytes = &value
		}
		if expires.Valid {
			value, _ := time.Parse(time.RFC3339Nano, expires.String)
			item.ExpiresAt = &value
		}
		item.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		item.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		item.RootIDs = s.shareIDs(r, "share_roots", "share_id", "node_id", item.ID)
		item.RecipientIDs = s.shareIDs(r, "share_recipients", "share_id", "user_id", item.ID)
		items = append(items, s.hydrateInternalShare(r, item))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) hydrateInternalShare(r *http.Request, item shares.InternalShare) map[string]any {
	roots := make([]files.Node, 0, len(item.RootIDs))
	for _, id := range item.RootIDs {
		if node, err := s.runtime.Files.Get(r.Context(), principal(r).UserID, id); err == nil {
			roots = append(roots, node)
		}
	}
	recipients := make([]map[string]any, 0, len(item.RecipientIDs))
	for _, id := range item.RecipientIDs {
		if user, err := s.runtime.AccountRepo.GetUserByID(r.Context(), id); err == nil {
			recipients = append(recipients, map[string]any{"id": user.ID, "username": user.Username, "email": user.Email, "display_name": user.DisplayName})
		}
	}
	return map[string]any{"id": item.ID, "owner_id": item.OwnerID, "roots": roots, "recipients": recipients, "permission": item.Permission, "expires_at": item.ExpiresAt, "allow_editor_uploads": item.AllowEditorUploads, "editor_allowance_bytes": item.EditorAllowanceBytes, "editor_used_bytes": item.EditorUsedBytes, "created_at": item.CreatedAt, "updated_at": item.UpdatedAt}
}

func (s *Server) shareIDs(r *http.Request, table, shareColumn, valueColumn, shareID string) []string {
	allowed := map[string]bool{"share_roots": true, "share_recipients": true, "public_share_roots": true}
	if !allowed[table] {
		return nil
	}
	rows, err := s.runtime.Database.Reader().QueryContext(r.Context(), fmt.Sprintf("SELECT %s FROM %s WHERE %s = ? ORDER BY %s", valueColumn, table, shareColumn, valueColumn), shareID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var value string
		if rows.Scan(&value) == nil {
			result = append(result, value)
		}
	}
	return result
}

func (s *Server) revokeShare(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	shareID := chi.URLParam(r, "shareID")
	recipients := s.shareIDs(r, "share_recipients", "share_id", "user_id", shareID)
	if err := s.runtime.Shares.RevokeInternal(r.Context(), p.UserID, shareID, p.Superadmin()); err != nil {
		s.handleError(w, r, err)
		return
	}
	if err := s.recordRequestAudit(r, "share.revoked", "share", shareID, nil); err != nil {
		s.handleError(w, r, err)
		return
	}
	for _, recipientID := range recipients {
		s.events.Publish(recipientID, Event{ID: randomID(8), Type: "share", Data: map[string]any{"share_id": shareID, "action": "revoked"}})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) shared(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	rows, err := s.runtime.Database.Reader().QueryContext(r.Context(), `SELECT DISTINCT sr.node_id FROM share_roots sr
		JOIN shares sh ON sh.id = sr.share_id JOIN share_recipients recipient ON recipient.share_id = sh.id
		JOIN nodes n ON n.id = sr.node_id
		WHERE recipient.user_id = ? AND sh.revoked_at IS NULL AND (sh.expires_at IS NULL OR sh.expires_at > ?)
		AND n.trashed_at IS NULL ORDER BY sr.node_id LIMIT 200`, p.UserID, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	defer rows.Close()
	items := make([]files.Node, 0)
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			if node, getErr := s.runtime.Files.Get(r.Context(), p.UserID, id); getErr == nil {
				items = append(items, node)
			}
		}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) createPublicShare(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeSharesWrite)) {
		return
	}
	var body struct {
		RootIDs         []string `json:"rootIds"`
		RootIDsAlt      []string `json:"root_ids"`
		TTLMinutes      int      `json:"ttlMinutes"`
		RedemptionLimit int      `json:"redemptionLimit"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	if len(body.RootIDs) == 0 {
		body.RootIDs = body.RootIDsAlt
	}
	if body.TTLMinutes == 0 {
		body.TTLMinutes = 10
	}
	if body.RedemptionLimit == 0 {
		body.RedemptionLimit = 3
	}
	created, err := s.runtime.Shares.CreatePublic(r.Context(), shares.CreatePublicInput{OwnerID: principal(r).UserID, RootIDs: body.RootIDs, TTL: time.Duration(body.TTLMinutes) * time.Minute, RedemptionLimit: body.RedemptionLimit})
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	if err := s.recordRequestAudit(r, "public_share.created", "public_share", created.ID, map[string]any{
		"root_ids": created.RootIDs, "expires_at": created.ExpiresAt, "redemption_limit": created.RedemptionLimit,
	}); err != nil {
		_ = s.runtime.Shares.RevokePublic(r.Context(), principal(r).UserID, created.ID, false)
		s.handleError(w, r, err)
		return
	}
	// Code is intentionally returned only by this response.
	WriteJSON(w, http.StatusCreated, s.hydratePublicShare(r, created))
}

func (s *Server) listPublicShares(w http.ResponseWriter, r *http.Request) {
	rows, err := s.runtime.Database.Reader().QueryContext(r.Context(), `SELECT id, owner_id, expires_at, redemption_limit, redemption_count,
		revoked_at, created_at FROM public_shares WHERE owner_id = ? ORDER BY created_at DESC LIMIT 200`, principal(r).UserID)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	defer rows.Close()
	items := make([]any, 0)
	for rows.Next() {
		var item shares.PublicShare
		var expires, created string
		var revoked sql.NullString
		if err := rows.Scan(&item.ID, &item.OwnerID, &expires, &item.RedemptionLimit, &item.RedemptionCount, &revoked, &created); err != nil {
			s.handleError(w, r, err)
			return
		}
		item.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
		item.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		item.Revoked = revoked.Valid
		item.RootIDs = s.shareIDs(r, "public_share_roots", "public_share_id", "node_id", item.ID)
		items = append(items, s.hydratePublicShare(r, item))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) hydratePublicShare(r *http.Request, item shares.PublicShare) map[string]any {
	roots := make([]files.Node, 0, len(item.RootIDs))
	for _, id := range item.RootIDs {
		if node, err := s.runtime.Files.Get(r.Context(), principal(r).UserID, id); err == nil {
			roots = append(roots, node)
		}
	}
	state := "active"
	if item.Revoked {
		state = "revoked"
	} else if !time.Now().Before(item.ExpiresAt) {
		state = "expired"
	} else if item.RedemptionCount >= item.RedemptionLimit {
		state = "exhausted"
	}
	result := map[string]any{"id": item.ID, "roots": roots, "expires_at": item.ExpiresAt, "redemption_limit": item.RedemptionLimit, "redemption_count": item.RedemptionCount, "state": state, "created_at": item.CreatedAt}
	if item.Code != "" {
		result["code"] = item.Code
	}
	return result
}

func (s *Server) revokePublicShare(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	shareID := chi.URLParam(r, "shareID")
	if err := s.runtime.Shares.RevokePublic(r.Context(), p.UserID, shareID, p.Superadmin()); err != nil {
		s.handleError(w, r, err)
		return
	}
	if err := s.recordRequestAudit(r, "public_share.revoked", "public_share", shareID, nil); err != nil {
		s.handleError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) publicExchange(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		s.publicExchangeFailure(w, r)
		return
	}
	session, err := s.runtime.Shares.Redeem(r.Context(), body.Code)
	if err != nil {
		if errors.Is(err, shares.ErrPublicUnavailable) {
			s.publicExchangeFailure(w, r)
		} else {
			// Preserve the same public response for operational errors without
			// treating an internal outage as a brute-force signal.
			s.genericPublicFailure(w, r)
		}
		return
	}
	if err := s.recordRequestAudit(r, "public_share.redeemed", "public_share", session.ShareID, nil); err != nil {
		_ = s.runtime.Shares.RevokePublic(r.Context(), "", session.ShareID, true)
		s.handleError(w, r, err)
		return
	}
	secure := s.cookiePolicy().Secure
	name := publicCookieName
	if !secure {
		name = "arca_public"
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: session.Token, Path: "/", Expires: session.ExpiresAt, MaxAge: int(time.Until(session.ExpiresAt).Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	WriteJSON(w, http.StatusOK, map[string]any{"redeemed": true, "expires_at": session.ExpiresAt})
}

func (s *Server) publicExchangeFailure(w http.ResponseWriter, r *http.Request) {
	if s.limiter != nil {
		s.limiter.RecordPublicExchangeFailure()
	}
	s.genericPublicFailure(w, r)
}

func (s *Server) genericPublicFailure(w http.ResponseWriter, r *http.Request) {
	WriteProblem(w, r, http.StatusNotFound, "public_share_unavailable", "Share unavailable", "The code is invalid or the share is no longer available.")
}

func (s *Server) publicSession(r *http.Request) (shares.PublicSession, error) {
	name := publicCookieName
	if !s.cookiePolicy().Secure {
		name = "arca_public"
	}
	cookie, err := r.Cookie(name)
	if err != nil {
		return shares.PublicSession{}, shares.ErrPublicUnavailable
	}
	return s.runtime.Shares.ResolvePublicSession(r.Context(), cookie.Value)
}

func (s *Server) publicBundle(w http.ResponseWriter, r *http.Request) {
	session, err := s.publicSession(r)
	if err != nil {
		s.genericPublicFailure(w, r)
		return
	}
	roots, err := s.runtime.Shares.PublicRoots(r.Context(), session.ShareID)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	items, rootNodes, err := s.publicNodes(r, session.ShareID, roots)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	WriteJSON(w, http.StatusOK, map[string]any{"name": "Shared bundle", "expires_at": session.ExpiresAt, "roots": rootNodes, "items": items})
}

func (s *Server) publicNodes(r *http.Request, shareID string, roots []string) ([]files.Node, []files.Node, error) {
	rootSet := make(map[string]bool, len(roots))
	for _, id := range roots {
		rootSet[id] = true
	}
	rows, err := s.runtime.Database.Reader().QueryContext(r.Context(), `WITH RECURSIVE visible(id, depth) AS (
		SELECT node_id, 0 FROM public_share_roots WHERE public_share_id = ?
		UNION ALL SELECT n.id, visible.depth + 1 FROM nodes n JOIN visible ON n.parent_id = visible.id WHERE n.trashed_at IS NULL AND visible.depth < 100
	) SELECT DISTINCT n.id, n.owner_id, n.parent_id, n.kind, n.name, n.mime_type, n.size_bytes, n.current_version_id,
		n.revision, n.created_by, n.trashed_at, n.original_parent_id, n.created_at, n.updated_at
		FROM nodes n JOIN visible ON visible.id = n.id WHERE n.trashed_at IS NULL LIMIT 5000`, shareID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var all, rootNodes []files.Node
	for rows.Next() {
		node, scanErr := scanPublicNode(rows)
		if scanErr != nil {
			return nil, nil, scanErr
		}
		all = append(all, node)
		if rootSet[node.ID] {
			rootNodes = append(rootNodes, node)
		}
	}
	sort.Slice(all, func(i, j int) bool { return strings.ToLower(all[i].Name) < strings.ToLower(all[j].Name) })
	return all, rootNodes, rows.Err()
}

func scanPublicNode(row interface{ Scan(...any) error }) (files.Node, error) {
	var node files.Node
	var parent, mimeType, versionID, trashed, original sql.NullString
	var kind, created, updated string
	if err := row.Scan(&node.ID, &node.OwnerID, &parent, &kind, &node.Name, &mimeType, &node.SizeBytes, &versionID, &node.Revision, &node.CreatedBy, &trashed, &original, &created, &updated); err != nil {
		return files.Node{}, err
	}
	node.Kind = files.Kind(kind)
	if parent.Valid {
		node.ParentID = &parent.String
	}
	if mimeType.Valid {
		node.MIMEType = &mimeType.String
	}
	if versionID.Valid {
		node.CurrentVersionID = &versionID.String
	}
	if original.Valid {
		node.OriginalParentID = &original.String
	}
	if trashed.Valid {
		value, _ := time.Parse(time.RFC3339Nano, trashed.String)
		node.TrashedAt = &value
	}
	node.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	node.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	node.Capabilities = files.Capabilities{Read: true}
	return node, nil
}

func (s *Server) publicContent(w http.ResponseWriter, r *http.Request) {
	session, err := s.publicSession(r)
	if err != nil {
		s.genericPublicFailure(w, r)
		return
	}
	nodeID := chi.URLParam(r, "nodeID")
	allowed, err := s.runtime.Shares.CanAccessPublicNode(r.Context(), session.ShareID, nodeID)
	if err != nil || !allowed {
		s.genericPublicFailure(w, r)
		return
	}
	resolved, err := s.resolvePublicContent(r, nodeID)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.serveResolvedContent(w, r, resolved, func() error {
		active, checkErr := s.runtime.Shares.ResolvePublicSession(r.Context(), publicCookieValue(s, r))
		if checkErr != nil || active.ShareID != session.ShareID {
			return shares.ErrPublicUnavailable
		}
		ok, checkErr := s.runtime.Shares.CanAccessPublicNode(r.Context(), session.ShareID, nodeID)
		if checkErr != nil || !ok {
			return shares.ErrPublicUnavailable
		}
		return nil
	})
}

func publicCookieValue(s *Server, r *http.Request) string {
	name := publicCookieName
	if !s.cookiePolicy().Secure {
		name = "arca_public"
	}
	cookie, _ := r.Cookie(name)
	if cookie == nil {
		return ""
	}
	return cookie.Value
}

func (s *Server) resolvePublicContent(r *http.Request, nodeID string) (files.Content, error) {
	var resolved files.Content
	var parent, mimeType, versionID, trashed, original sql.NullString
	var kind, created, updated string
	if err := s.runtime.Database.Reader().QueryRowContext(r.Context(), `SELECT id, owner_id, parent_id, kind, name, mime_type, size_bytes, current_version_id,
		revision, created_by, trashed_at, original_parent_id, created_at, updated_at FROM nodes WHERE id = ?`, nodeID).Scan(
		&resolved.Node.ID, &resolved.Node.OwnerID, &parent, &kind, &resolved.Node.Name, &mimeType, &resolved.Node.SizeBytes, &versionID,
		&resolved.Node.Revision, &resolved.Node.CreatedBy, &trashed, &original, &created, &updated); err != nil {
		return files.Content{}, err
	}
	if !versionID.Valid || kind != "file" || trashed.Valid {
		return files.Content{}, files.NewError(files.CodeNotFound, "public content", nodeID, "file not found")
	}
	resolved.Node.Kind = files.KindFile
	resolved.Node.CurrentVersionID = &versionID.String
	if parent.Valid {
		resolved.Node.ParentID = &parent.String
	}
	if mimeType.Valid {
		resolved.Node.MIMEType = &mimeType.String
	}
	var versionCreated string
	if err := s.runtime.Database.Reader().QueryRowContext(r.Context(), `SELECT v.id, v.node_id, v.blob_id, v.sequence, v.size_bytes, v.sha256,
		v.mime_type, v.created_by, v.created_at, b.storage_key, b.state FROM file_versions v JOIN blobs b ON b.id = v.blob_id
		WHERE v.id = ? AND v.node_id = ? AND b.state = 'ready'`, versionID.String, nodeID).Scan(&resolved.Version.ID, &resolved.Version.NodeID,
		&resolved.Version.BlobID, &resolved.Version.Sequence, &resolved.Version.SizeBytes, &resolved.Version.SHA256, &resolved.Version.MIMEType,
		&resolved.Version.CreatedBy, &versionCreated, &resolved.StorageKey, &resolved.BlobState); err != nil {
		return files.Content{}, err
	}
	resolved.Version.CreatedAt, _ = time.Parse(time.RFC3339Nano, versionCreated)
	return resolved, nil
}

var _ = errors.Is
