package httpapi

import (
	"archive/zip"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"

	"arca/internal/accounts"
	"arca/internal/audit"
	"arca/internal/auth"
	"arca/internal/database"
	"arca/internal/files"
	"arca/internal/preview"
	"arca/internal/uploads"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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
	supportUserID := strings.TrimSpace(r.URL.Query().Get("support_user"))
	if supportUserID != "" {
		target, err := s.validateSupportBrowse(r, supportUserID)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		if parentID == "" {
			parentID = target.RootNodeID
		} else {
			parent, getErr := s.runtime.Files.Get(r.Context(), p.UserID, parentID)
			if getErr != nil {
				s.handleError(w, r, getErr)
				return
			}
			if parent.OwnerID != supportUserID {
				s.handleError(w, r, accounts.ErrForbidden)
				return
			}
		}
	}
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
	if err := s.auditSupportRead(r, parentID, "support_access.folder_opened"); err != nil {
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

func (s *Server) validateSupportBrowse(r *http.Request, targetUserID string) (*accounts.User, error) {
	p := principal(r)
	if !p.Superadmin() {
		return nil, accounts.ErrForbidden
	}
	access, err := s.runtime.AccountRepo.GetActiveSupportAccess(r.Context(), p.UserID)
	if err != nil {
		if errors.Is(err, accounts.ErrNotFound) {
			return nil, accounts.ErrForbidden
		}
		return nil, err
	}
	if access.TargetUserID != targetUserID {
		return nil, accounts.ErrForbidden
	}
	target, err := s.runtime.AccountRepo.GetUserByID(r.Context(), targetUserID)
	if err != nil {
		return nil, err
	}
	if target.RootNodeID == "" {
		return nil, accounts.ErrNotFound
	}
	return target, nil
}

func (s *Server) validateSupportNodeQuery(r *http.Request, node files.Node) error {
	targetUserID := strings.TrimSpace(r.URL.Query().Get("support_user"))
	if targetUserID == "" {
		return nil
	}
	if _, err := s.validateSupportBrowse(r, targetUserID); err != nil {
		return err
	}
	if node.OwnerID != targetUserID {
		return accounts.ErrForbidden
	}
	return nil
}

func (s *Server) auditSupportRead(r *http.Request, nodeID, action string) error {
	p := principal(r)
	access, err := files.Authorize(r.Context(), s.runtime.Database.Reader(), p.UserID, nodeID, files.ActionRead, time.Now().UTC())
	if err != nil {
		return err
	}
	if !access.Support {
		return nil
	}
	grant, err := s.runtime.AccountRepo.GetActiveSupportAccess(r.Context(), p.UserID)
	if err != nil {
		return err
	}
	if grant.TargetUserID != access.OwnerID {
		return accounts.ErrForbidden
	}
	if s.runtime.Audit == nil {
		return errors.New("support access audit recorder is unavailable")
	}
	actorID := p.UserID
	return s.runtime.Audit.Record(r.Context(), audit.Event{
		ActorID: &actorID, Action: action, TargetType: "node", TargetID: nodeID,
		IPAddress: s.remoteIP(r), UserAgent: r.UserAgent(), RequestID: RequestID(r.Context()),
		Metadata: map[string]any{"support_access_id": grant.ID, "target_user_id": grant.TargetUserID},
	})
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
	if err := s.validateSupportNodeQuery(r, node); err != nil {
		s.handleError(w, r, err)
		return
	}
	if err := s.auditSupportRead(r, node.ID, "support_access.item_opened"); err != nil {
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

func (s *Server) copyNode(w http.ResponseWriter, r *http.Request) {
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
	node, err := s.runtime.Files.Copy(r.Context(), files.CopyRequest{ActorID: p.UserID, NodeID: chi.URLParam(r, "nodeID"), DestinationID: body.ParentID, Name: body.Name})
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusCreated, node)
}

func (s *Server) saveNodeCopy(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeFilesWrite)) {
		return
	}
	var body struct {
		ParentID    string               `json:"parent_id"`
		ParentIDAlt string               `json:"parentId"`
		Name        string               `json:"name"`
		Conflict    uploads.ConflictMode `json:"conflict"`
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
	if body.Conflict == "" {
		body.Conflict = uploads.ConflictKeepBoth
	}
	if body.Conflict != uploads.ConflictFail && body.Conflict != uploads.ConflictKeepBoth {
		s.handleError(w, r, files.NewError(files.CodeInvalid, "save file copy", chi.URLParam(r, "nodeID"), "conflict must be fail or keep_both"))
		return
	}
	sourceID := chi.URLParam(r, "nodeID")
	sourceAccess, err := files.Authorize(r.Context(), s.runtime.Database.Reader(), p.UserID, sourceID, files.ActionRead, time.Now().UTC())
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	if sourceAccess.Support {
		s.handleError(w, r, files.NewError(files.CodeForbidden, "save file copy", sourceID, "support access cannot save copies"))
		return
	}
	destination, err := s.runtime.Files.Get(r.Context(), p.UserID, body.ParentID)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	if destination.OwnerID != p.UserID || destination.Kind != files.KindFolder {
		s.handleError(w, r, files.NewError(files.CodeForbidden, "save file copy", body.ParentID, "destination must be a folder owned by the recipient"))
		return
	}
	upload, err := s.runtime.Uploads.SaveCopy(r.Context(), uploads.SaveCopyRequest{
		ActorID: p.UserID, SourceNodeID: sourceID, DestinationID: body.ParentID,
		Name: body.Name, ConflictMode: body.Conflict,
	})
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	if upload.NodeID != nil {
		w.Header().Set("Location", "/api/v1/nodes/"+*upload.NodeID)
	}
	WriteJSON(w, http.StatusCreated, upload)
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

const maxBulkRoots = 500

type bulkMutationRequest struct {
	Action           string             `json:"action"`
	Items            []bulkMutationItem `json:"items"`
	DestinationID    string             `json:"destination_id"`
	DestinationIDAlt string             `json:"destinationId"`
}

type bulkMutationItem struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision,omitempty"`
	IfMatch  string `json:"if_match,omitempty"`
}

type bulkMutationResultItem struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision,omitempty"`
	Purged   bool   `json:"purged,omitempty"`
}

type bulkNodeState struct {
	ID               string
	OwnerID          string
	ParentID         sql.NullString
	Kind             files.Kind
	Name             string
	NameKey          string
	Revision         int64
	TrashedAt        sql.NullString
	OriginalParentID sql.NullString
}

type bulkMutationPlan struct {
	item          bulkMutationItem
	node          bulkNodeState
	revision      int64
	destinationID string
}

type bulkPurgePlan struct {
	bulkMutationPlan
	treeIDs    []string
	blobCounts map[string]int64
}

func (s *Server) bulkNodes(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeFilesWrite)) {
		return
	}
	var body bulkMutationRequest
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	if body.DestinationID == "" {
		body.DestinationID = body.DestinationIDAlt
	}
	body.Action = strings.ToLower(strings.TrimSpace(body.Action))
	if body.Action != "move" && body.Action != "trash" && body.Action != "restore" && body.Action != "purge" {
		s.handleError(w, r, files.NewError(files.CodeInvalid, "bulk mutate nodes", "", "action must be move, trash, restore, or purge"))
		return
	}
	if len(body.Items) == 0 || len(body.Items) > maxBulkRoots {
		s.handleError(w, r, files.NewError(files.CodeInvalid, "bulk mutate nodes", "", "select between 1 and 500 roots"))
		return
	}
	seen := make(map[string]struct{}, len(body.Items))
	for index := range body.Items {
		body.Items[index].ID = strings.TrimSpace(body.Items[index].ID)
		if body.Items[index].ID == "" {
			s.handleError(w, r, files.NewError(files.CodeInvalid, "bulk mutate nodes", "", "every item requires an id"))
			return
		}
		if _, exists := seen[body.Items[index].ID]; exists {
			s.handleError(w, r, files.NewError(files.CodeInvalid, "bulk mutate nodes", body.Items[index].ID, "duplicate root"))
			return
		}
		seen[body.Items[index].ID] = struct{}{}
		revision, err := bulkItemRevision(body.Items[index])
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		body.Items[index].Revision = revision
	}
	if body.Action == "move" && strings.TrimSpace(body.DestinationID) == "" {
		s.handleError(w, r, files.NewError(files.CodeInvalid, "bulk move nodes", "", "destination_id is required"))
		return
	}

	tx, err := s.runtime.Database.BeginImmediate(r.Context())
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := validateBulkRootsDoNotOverlap(r.Context(), tx, body.Items); err != nil {
		s.handleError(w, r, err)
		return
	}
	now := time.Now().UTC()
	actorID := principal(r).UserID
	var resultItems []bulkMutationResultItem
	var purgeResult files.PurgeResult
	switch body.Action {
	case "move":
		resultItems, err = validateAndApplyBulkMove(r.Context(), tx, actorID, strings.TrimSpace(body.DestinationID), body.Items, now)
	case "trash":
		resultItems, err = validateAndApplyBulkTrash(r.Context(), tx, actorID, body.Items, now)
	case "restore":
		resultItems, err = validateAndApplyBulkRestore(r.Context(), tx, actorID, body.Items, now)
	case "purge":
		resultItems, purgeResult, err = validateAndApplyBulkPurge(r.Context(), tx, actorID, body.Items, now)
	}
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.handleError(w, r, err)
		return
	}
	response := map[string]any{"action": body.Action, "items": resultItems}
	if body.Action == "purge" {
		response["summary"] = purgeResult
	}
	WriteJSON(w, http.StatusOK, response)
}

func bulkItemRevision(item bulkMutationItem) (int64, error) {
	revision := item.Revision
	if strings.TrimSpace(item.IfMatch) != "" {
		value := strings.Trim(strings.TrimSpace(item.IfMatch), `"`)
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed <= 0 {
			return 0, files.NewError(files.CodePreconditionRequired, "bulk mutate nodes", item.ID, "if_match must contain a positive revision")
		}
		if revision > 0 && revision != parsed {
			return 0, files.NewError(files.CodeInvalid, "bulk mutate nodes", item.ID, "revision and if_match disagree")
		}
		revision = parsed
	}
	if revision <= 0 {
		return 0, files.NewError(files.CodePreconditionRequired, "bulk mutate nodes", item.ID, "each item requires a positive revision or if_match")
	}
	return revision, nil
}

func loadBulkNode(ctx context.Context, q database.Queryer, nodeID string) (bulkNodeState, error) {
	var node bulkNodeState
	err := q.QueryRowContext(ctx, `SELECT id, owner_id, parent_id, kind, name, name_key, revision, trashed_at, original_parent_id
		FROM nodes WHERE id = ?`, nodeID).Scan(&node.ID, &node.OwnerID, &node.ParentID, &node.Kind, &node.Name,
		&node.NameKey, &node.Revision, &node.TrashedAt, &node.OriginalParentID)
	if errors.Is(err, sql.ErrNoRows) {
		return bulkNodeState{}, files.NewError(files.CodeNotFound, "bulk mutate nodes", nodeID, "node not found")
	}
	if err != nil {
		return bulkNodeState{}, files.WrapError(files.CodeInvalid, "bulk mutate nodes", nodeID, err)
	}
	return node, nil
}

func validateBulkRootsDoNotOverlap(ctx context.Context, q database.Queryer, items []bulkMutationItem) error {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(items)), ",")
	args := make([]any, 0, len(items)*2)
	for _, item := range items {
		args = append(args, item.ID)
	}
	for _, item := range items {
		args = append(args, item.ID)
	}
	query := `WITH RECURSIVE ancestry(root_id, id, parent_id, depth) AS (
		SELECT id, id, parent_id, 0 FROM nodes WHERE id IN (` + placeholders + `)
		UNION ALL SELECT a.root_id, p.id, p.parent_id, a.depth + 1
		FROM ancestry a JOIN nodes p ON p.id = a.parent_id WHERE a.depth < 100
	) SELECT root_id, id FROM ancestry WHERE depth > 0 AND id IN (` + placeholders + `) LIMIT 1`
	var descendant, ancestor string
	err := q.QueryRowContext(ctx, query, args...).Scan(&descendant, &ancestor)
	if err == nil {
		return files.NewError(files.CodeConflict, "bulk mutate nodes", descendant, "selected roots overlap through ancestor "+ancestor)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return files.WrapError(files.CodeInvalid, "bulk mutate nodes", "", err)
}

func validateBulkActor(ctx context.Context, q database.Queryer, actorID string) error {
	var state string
	if err := q.QueryRowContext(ctx, "SELECT state FROM users WHERE id = ?", actorID).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return files.NewError(files.CodeNotFound, "bulk mutate nodes", actorID, "actor not found")
		}
		return err
	}
	if state != "active" && state != "over_quota" {
		return files.NewError(files.CodeForbidden, "bulk mutate nodes", actorID, "account is not active")
	}
	return nil
}

func validateAndApplyBulkMove(ctx context.Context, tx *database.ImmediateTx, actorID, destinationID string, items []bulkMutationItem, now time.Time) ([]bulkMutationResultItem, error) {
	destinationAccess, err := files.Authorize(ctx, tx, actorID, destinationID, files.ActionCreateChild, now)
	if err != nil {
		return nil, err
	}
	destination, err := loadBulkNode(ctx, tx, destinationID)
	if err != nil {
		return nil, err
	}
	if destination.Kind != files.KindFolder {
		return nil, files.NewError(files.CodeInvalid, "bulk move nodes", destinationID, "destination is not a folder")
	}
	destinationDepth, err := bulkAncestorDepth(ctx, tx, destinationID)
	if err != nil {
		return nil, err
	}
	plans := make([]bulkMutationPlan, 0, len(items))
	names := make(map[string]string, len(items))
	for _, item := range items {
		access, err := files.Authorize(ctx, tx, actorID, item.ID, files.ActionMove, now)
		if err != nil {
			return nil, err
		}
		if access.OwnerID != destinationAccess.OwnerID {
			return nil, files.NewError(files.CodeForbidden, "bulk move nodes", item.ID, "cannot move nodes across owners")
		}
		node, err := loadBulkNode(ctx, tx, item.ID)
		if err != nil {
			return nil, err
		}
		if node.Revision != item.Revision {
			return nil, files.NewError(files.CodeRevisionMismatch, "bulk move nodes", item.ID, "resource changed since it was read")
		}
		if !node.ParentID.Valid {
			return nil, files.NewError(files.CodeForbidden, "bulk move nodes", item.ID, "root cannot be moved")
		}
		if node.Kind == files.KindFolder {
			var cycle int
			err := tx.QueryRowContext(ctx, `WITH RECURSIVE descendants(id, depth) AS (
				SELECT id, 0 FROM nodes WHERE id = ?
				UNION ALL SELECT n.id, d.depth + 1 FROM nodes n JOIN descendants d ON n.parent_id = d.id WHERE d.depth < 100
			) SELECT 1 FROM descendants WHERE id = ? LIMIT 1`, item.ID, destinationID).Scan(&cycle)
			if err == nil {
				return nil, files.NewError(files.CodeCycle, "bulk move nodes", item.ID, "folder cannot be moved into itself or a descendant")
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
		}
		height, err := bulkDescendantHeight(ctx, tx, item.ID)
		if err != nil {
			return nil, err
		}
		if destinationDepth+1+height > 100 {
			return nil, files.NewError(files.CodeInvalid, "bulk move nodes", item.ID, "move would exceed the maximum tree depth of 100")
		}
		if previous, exists := names[node.NameKey]; exists && previous != item.ID {
			return nil, files.NewError(files.CodeConflict, "bulk move nodes", item.ID, "selected roots have conflicting names")
		}
		names[node.NameKey] = item.ID
		var collision string
		err = tx.QueryRowContext(ctx, `SELECT id FROM nodes WHERE owner_id = ? AND parent_id = ? AND name_key = ?
			AND trashed_at IS NULL AND id <> ? LIMIT 1`, destinationAccess.OwnerID, destinationID, node.NameKey, item.ID).Scan(&collision)
		if err == nil {
			return nil, files.NewError(files.CodeConflict, "bulk move nodes", item.ID, "destination already contains this name")
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		plans = append(plans, bulkMutationPlan{item: item, node: node, revision: item.Revision, destinationID: destinationID})
	}
	results := make([]bulkMutationResultItem, 0, len(plans))
	for _, plan := range plans {
		result, err := tx.ExecContext(ctx, `UPDATE nodes SET parent_id = ?, revision = revision + 1, updated_at = ?
			WHERE id = ? AND revision = ? AND trashed_at IS NULL`, plan.destinationID, now.Format(time.RFC3339Nano), plan.node.ID, plan.revision)
		if err != nil {
			return nil, bulkWriteError("bulk move nodes", plan.node.ID, err)
		}
		if err := requireBulkAffected(result, "bulk move nodes", plan.node.ID); err != nil {
			return nil, err
		}
		results = append(results, bulkMutationResultItem{ID: plan.node.ID, Revision: plan.revision + 1})
	}
	return results, nil
}

func validateAndApplyBulkTrash(ctx context.Context, tx *database.ImmediateTx, actorID string, items []bulkMutationItem, now time.Time) ([]bulkMutationResultItem, error) {
	plans := make([]bulkMutationPlan, 0, len(items))
	for _, item := range items {
		if _, err := files.Authorize(ctx, tx, actorID, item.ID, files.ActionTrash, now); err != nil {
			return nil, err
		}
		node, err := loadBulkNode(ctx, tx, item.ID)
		if err != nil {
			return nil, err
		}
		if node.Revision != item.Revision {
			return nil, files.NewError(files.CodeRevisionMismatch, "bulk trash nodes", item.ID, "resource changed since it was read")
		}
		if !node.ParentID.Valid {
			return nil, files.NewError(files.CodeForbidden, "bulk trash nodes", item.ID, "root cannot be trashed")
		}
		plans = append(plans, bulkMutationPlan{item: item, node: node, revision: item.Revision})
	}
	results := make([]bulkMutationResultItem, 0, len(plans))
	stamp := now.Format(time.RFC3339Nano)
	for _, plan := range plans {
		result, err := tx.ExecContext(ctx, `UPDATE nodes SET trashed_at = ?, original_parent_id = parent_id,
			revision = revision + 1, updated_at = ? WHERE id = ? AND revision = ? AND trashed_at IS NULL`,
			stamp, stamp, plan.node.ID, plan.revision)
		if err != nil {
			return nil, bulkWriteError("bulk trash nodes", plan.node.ID, err)
		}
		if err := requireBulkAffected(result, "bulk trash nodes", plan.node.ID); err != nil {
			return nil, err
		}
		results = append(results, bulkMutationResultItem{ID: plan.node.ID, Revision: plan.revision + 1})
	}
	return results, nil
}

func validateAndApplyBulkRestore(ctx context.Context, tx *database.ImmediateTx, actorID string, items []bulkMutationItem, now time.Time) ([]bulkMutationResultItem, error) {
	if err := validateBulkActor(ctx, tx, actorID); err != nil {
		return nil, err
	}
	var rootID string
	if err := tx.QueryRowContext(ctx, "SELECT root_node_id FROM users WHERE id = ?", actorID).Scan(&rootID); err != nil || rootID == "" {
		return nil, files.WrapError(files.CodeInvalidState, "bulk restore nodes", actorID, err)
	}
	plans := make([]bulkMutationPlan, 0, len(items))
	destinationNames := make(map[string]string, len(items))
	for _, item := range items {
		node, err := loadBulkNode(ctx, tx, item.ID)
		if err != nil {
			return nil, err
		}
		if node.OwnerID != actorID || !node.TrashedAt.Valid || !node.ParentID.Valid {
			return nil, files.NewError(files.CodeForbidden, "bulk restore nodes", item.ID, "only the owner can restore a trash root")
		}
		if node.Revision != item.Revision {
			return nil, files.NewError(files.CodeRevisionMismatch, "bulk restore nodes", item.ID, "resource changed since it was read")
		}
		destinationID := rootID
		if node.OriginalParentID.Valid {
			valid, validErr := bulkRestoreDestinationValid(ctx, tx, actorID, node.OriginalParentID.String)
			if validErr != nil {
				return nil, validErr
			}
			if valid {
				destinationID = node.OriginalParentID.String
			}
		}
		if _, err := files.Authorize(ctx, tx, actorID, destinationID, files.ActionCreateChild, now); err != nil {
			return nil, err
		}
		key := destinationID + "\x00" + node.NameKey
		if previous, exists := destinationNames[key]; exists && previous != node.ID {
			return nil, files.NewError(files.CodeConflict, "bulk restore nodes", node.ID, "selected roots have conflicting restore names")
		}
		destinationNames[key] = node.ID
		var collision string
		err = tx.QueryRowContext(ctx, `SELECT id FROM nodes WHERE owner_id = ? AND parent_id = ? AND name_key = ?
			AND trashed_at IS NULL AND id <> ? LIMIT 1`, actorID, destinationID, node.NameKey, node.ID).Scan(&collision)
		if err == nil {
			return nil, files.NewError(files.CodeConflict, "bulk restore nodes", node.ID, "restore destination already contains this name")
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		plans = append(plans, bulkMutationPlan{item: item, node: node, revision: item.Revision, destinationID: destinationID})
	}
	stamp := now.Format(time.RFC3339Nano)
	results := make([]bulkMutationResultItem, 0, len(plans))
	for _, plan := range plans {
		result, err := tx.ExecContext(ctx, `UPDATE nodes SET parent_id = ?, trashed_at = NULL, original_parent_id = NULL,
			revision = revision + 1, updated_at = ? WHERE id = ? AND owner_id = ? AND revision = ? AND trashed_at IS NOT NULL`,
			plan.destinationID, stamp, plan.node.ID, actorID, plan.revision)
		if err != nil {
			return nil, bulkWriteError("bulk restore nodes", plan.node.ID, err)
		}
		if err := requireBulkAffected(result, "bulk restore nodes", plan.node.ID); err != nil {
			return nil, err
		}
		results = append(results, bulkMutationResultItem{ID: plan.node.ID, Revision: plan.revision + 1})
	}
	return results, nil
}

func validateAndApplyBulkPurge(ctx context.Context, tx *database.ImmediateTx, actorID string, items []bulkMutationItem, now time.Time) ([]bulkMutationResultItem, files.PurgeResult, error) {
	if err := validateBulkActor(ctx, tx, actorID); err != nil {
		return nil, files.PurgeResult{}, err
	}
	plans := make([]bulkPurgePlan, 0, len(items))
	totalBlobCounts := make(map[string]int64)
	result := files.PurgeResult{}
	for _, item := range items {
		node, err := loadBulkNode(ctx, tx, item.ID)
		if err != nil {
			return nil, files.PurgeResult{}, err
		}
		if node.OwnerID != actorID || !node.TrashedAt.Valid || !node.ParentID.Valid {
			return nil, files.PurgeResult{}, files.NewError(files.CodeForbidden, "bulk purge nodes", item.ID, "only an owner may purge a trash root")
		}
		if node.Revision != item.Revision {
			return nil, files.PurgeResult{}, files.NewError(files.CodeRevisionMismatch, "bulk purge nodes", item.ID, "resource changed since it was read")
		}
		var pending int
		err = tx.QueryRowContext(ctx, `WITH RECURSIVE tree(id) AS (
			SELECT id FROM nodes WHERE id = ? UNION ALL SELECT n.id FROM nodes n JOIN tree t ON n.parent_id = t.id
		) SELECT COUNT(*) FROM uploads WHERE (parent_id IN (SELECT id FROM tree) OR replace_node_id IN (SELECT id FROM tree))
			AND state IN ('pending', 'finalizing')`, item.ID).Scan(&pending)
		if err != nil {
			return nil, files.PurgeResult{}, err
		}
		if pending != 0 {
			return nil, files.PurgeResult{}, files.NewError(files.CodeConflict, "bulk purge nodes", item.ID, "tree has active uploads")
		}
		treeIDs, blobCounts, err := bulkPurgeTree(ctx, tx, item.ID)
		if err != nil {
			return nil, files.PurgeResult{}, err
		}
		for blobID, count := range blobCounts {
			totalBlobCounts[blobID] += count
			result.VersionsDeleted += count
		}
		result.NodesDeleted += int64(len(treeIDs))
		plans = append(plans, bulkPurgePlan{bulkMutationPlan: bulkMutationPlan{item: item, node: node, revision: item.Revision}, treeIDs: treeIDs, blobCounts: blobCounts})
	}
	deleteAfter := now.Add(24 * time.Hour).Format(time.RFC3339Nano)
	stamp := now.Format(time.RFC3339Nano)
	var releasedBytes int64
	for blobID, count := range totalBlobCounts {
		var refCount, blobSize int64
		if err := tx.QueryRowContext(ctx, "SELECT ref_count, size_bytes FROM blobs WHERE id = ?", blobID).Scan(&refCount, &blobSize); err != nil {
			return nil, files.PurgeResult{}, err
		}
		if refCount < count {
			return nil, files.PurgeResult{}, files.NewError(files.CodeInvalidState, "bulk purge nodes", blobID, "blob reference count is inconsistent")
		}
		if refCount == count {
			releasedBytes += blobSize
			result.BlobsQueued++
		}
	}
	for blobID, count := range totalBlobCounts {
		update, err := tx.ExecContext(ctx, `UPDATE blobs SET ref_count = ref_count - ?,
			state = CASE WHEN ref_count <= ? THEN 'deleting' ELSE state END,
			delete_after = CASE WHEN ref_count <= ? THEN ? ELSE delete_after END
			WHERE id = ? AND ref_count >= ?`, count, count, count, deleteAfter, blobID, count)
		if err != nil {
			return nil, files.PurgeResult{}, err
		}
		if affected, _ := update.RowsAffected(); affected != 1 {
			return nil, files.PurgeResult{}, files.NewError(files.CodeInvalidState, "bulk purge nodes", blobID, "blob reference count is inconsistent")
		}
	}
	if releasedBytes > 0 {
		quotaResult, err := tx.ExecContext(ctx, `UPDATE users SET used_bytes = used_bytes - ?, updated_at = ?
			WHERE id = ? AND used_bytes >= ?`, releasedBytes, stamp, actorID, releasedBytes)
		if err != nil {
			return nil, files.PurgeResult{}, err
		}
		if affected, _ := quotaResult.RowsAffected(); affected != 1 {
			return nil, files.PurgeResult{}, files.NewError(files.CodeInvalidState, "bulk purge nodes", actorID, "used-byte accounting is inconsistent")
		}
	}
	results := make([]bulkMutationResultItem, 0, len(plans))
	for _, plan := range plans {
		for _, nodeID := range plan.treeIDs {
			if _, err := tx.ExecContext(ctx, `DELETE FROM uploads WHERE (parent_id = ? OR replace_node_id = ?)
				AND state IN ('completed', 'cancelled', 'expired', 'failed')`, nodeID, nodeID); err != nil {
				return nil, files.PurgeResult{}, err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM file_versions WHERE node_id = ?", nodeID); err != nil {
				return nil, files.PurgeResult{}, err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM share_roots WHERE node_id = ?", nodeID); err != nil {
				return nil, files.PurgeResult{}, err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM public_share_roots WHERE node_id = ?", nodeID); err != nil {
				return nil, files.PurgeResult{}, err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM nodes WHERE id = ?", nodeID); err != nil {
				return nil, files.PurgeResult{}, bulkWriteError("bulk purge nodes", nodeID, err)
			}
		}
		results = append(results, bulkMutationResultItem{ID: plan.node.ID, Purged: true})
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM shares WHERE NOT EXISTS (SELECT 1 FROM share_roots WHERE share_id = shares.id)"); err != nil {
		return nil, files.PurgeResult{}, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM public_shares WHERE NOT EXISTS (SELECT 1 FROM public_share_roots WHERE public_share_id = public_shares.id)"); err != nil {
		return nil, files.PurgeResult{}, err
	}
	if result.BlobsQueued > 0 {
		jobID, err := uuid.NewV7()
		if err != nil {
			return nil, files.PurgeResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO jobs(id, kind, payload, state, run_after, created_at, updated_at)
			VALUES (?, 'blobs.gc', '{}', 'queued', ?, ?, ?)`, jobID.String(), deleteAfter, stamp, stamp); err != nil {
			return nil, files.PurgeResult{}, err
		}
	}
	return results, result, nil
}

func bulkRestoreDestinationValid(ctx context.Context, q database.Queryer, actorID, nodeID string) (bool, error) {
	var valid int
	err := q.QueryRowContext(ctx, `WITH RECURSIVE ancestors(id, parent_id, trashed_at, owner_id, kind, depth) AS (
		SELECT id, parent_id, trashed_at, owner_id, kind, 0 FROM nodes WHERE id = ? AND owner_id = ? AND kind = 'folder'
		UNION ALL SELECT n.id, n.parent_id, n.trashed_at, n.owner_id, n.kind, a.depth + 1
		FROM nodes n JOIN ancestors a ON n.id = a.parent_id WHERE a.depth < 100
	) SELECT 1 WHERE EXISTS (SELECT 1 FROM ancestors) AND NOT EXISTS (SELECT 1 FROM ancestors WHERE trashed_at IS NOT NULL)`, nodeID, actorID).Scan(&valid)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func bulkPurgeTree(ctx context.Context, q database.Queryer, rootID string) ([]string, map[string]int64, error) {
	rows, err := q.QueryContext(ctx, `WITH RECURSIVE tree(id, depth) AS (
		SELECT id, 0 FROM nodes WHERE id = ? UNION ALL SELECT n.id, t.depth + 1
		FROM nodes n JOIN tree t ON n.parent_id = t.id WHERE t.depth < 100
	) SELECT id, depth FROM tree ORDER BY depth DESC, id`, rootID)
	if err != nil {
		return nil, nil, err
	}
	var treeIDs []string
	for rows.Next() {
		var nodeID string
		var depth int
		if err := rows.Scan(&nodeID, &depth); err != nil {
			rows.Close()
			return nil, nil, err
		}
		treeIDs = append(treeIDs, nodeID)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, err
	}
	if len(treeIDs) == 0 {
		return nil, nil, files.NewError(files.CodeNotFound, "bulk purge nodes", rootID, "node not found")
	}
	counts := make(map[string]int64)
	for _, nodeID := range treeIDs {
		versionRows, err := q.QueryContext(ctx, "SELECT blob_id, COUNT(*) FROM file_versions WHERE node_id = ? GROUP BY blob_id", nodeID)
		if err != nil {
			return nil, nil, err
		}
		for versionRows.Next() {
			var blobID string
			var count int64
			if err := versionRows.Scan(&blobID, &count); err != nil {
				versionRows.Close()
				return nil, nil, err
			}
			counts[blobID] += count
		}
		if err := versionRows.Close(); err != nil {
			return nil, nil, err
		}
	}
	return treeIDs, counts, nil
}

func bulkAncestorDepth(ctx context.Context, q database.Queryer, nodeID string) (int, error) {
	var depth int
	err := q.QueryRowContext(ctx, `WITH RECURSIVE ancestors(id, parent_id, depth) AS (
		SELECT id, parent_id, 0 FROM nodes WHERE id = ?
		UNION ALL SELECT n.id, n.parent_id, a.depth + 1 FROM nodes n JOIN ancestors a ON n.id = a.parent_id WHERE a.depth <= 100
	) SELECT COALESCE(MAX(depth), 0) FROM ancestors`, nodeID).Scan(&depth)
	if err != nil {
		return 0, err
	}
	if depth > 100 {
		return 0, files.NewError(files.CodeInvalidState, "bulk move nodes", nodeID, "tree exceeds maximum depth")
	}
	return depth, nil
}

func bulkDescendantHeight(ctx context.Context, q database.Queryer, nodeID string) (int, error) {
	var height int
	err := q.QueryRowContext(ctx, `WITH RECURSIVE descendants(id, depth) AS (
		SELECT id, 0 FROM nodes WHERE id = ?
		UNION ALL SELECT n.id, d.depth + 1 FROM nodes n JOIN descendants d ON n.parent_id = d.id WHERE d.depth <= 100
	) SELECT COALESCE(MAX(depth), 0) FROM descendants`, nodeID).Scan(&height)
	if err != nil {
		return 0, err
	}
	if height > 100 {
		return 0, files.NewError(files.CodeInvalidState, "bulk move nodes", nodeID, "tree exceeds maximum depth")
	}
	return height, nil
}

func requireBulkAffected(result sql.Result, op, resource string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return files.NewError(files.CodeRevisionMismatch, op, resource, "resource changed since it was read")
	}
	return nil
}

func bulkWriteError(op, resource string, err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "UNIQUE constraint failed") || strings.Contains(err.Error(), "constraint failed: UNIQUE") {
		return files.WrapError(files.CodeConflict, op, resource, err)
	}
	if strings.Contains(err.Error(), "FOREIGN KEY constraint failed") || strings.Contains(err.Error(), "constraint failed: FOREIGN KEY") {
		return files.WrapError(files.CodeInvalid, op, resource, err)
	}
	return fmt.Errorf("%s: %w", op, err)
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
	if err := s.validateSupportNodeQuery(r, resolved.Node); err != nil {
		s.handleError(w, r, err)
		return
	}
	if err := s.auditSupportRead(r, resolved.Node.ID, "support_access.content_downloaded"); err != nil {
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

const (
	maxArchiveRoots   = 500
	maxArchiveEntries = 100_000
	archiveCopyBuffer = 1 << 20
)

type archiveRequest struct {
	Roots   []string `json:"roots"`
	NodeIDs []string `json:"node_ids"`
	Name    string   `json:"name,omitempty"`
}

type archiveEntry struct {
	Node        files.Node
	ArchivePath string
}

func (s *Server) archiveNodes(w http.ResponseWriter, r *http.Request) {
	if !s.checkScope(w, r, string(auth.ScopeFilesRead)) {
		return
	}
	var body archiveRequest
	if err := decodeBody(w, r, &body); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
		return
	}
	if len(body.Roots) == 0 {
		body.Roots = body.NodeIDs
	} else if len(body.NodeIDs) != 0 {
		s.handleError(w, r, files.NewError(files.CodeInvalid, "create archive", "", "provide roots or node_ids, not both"))
		return
	}
	if len(body.Roots) == 0 || len(body.Roots) > maxArchiveRoots {
		s.handleError(w, r, files.NewError(files.CodeInvalid, "create archive", "", "select between 1 and 500 roots"))
		return
	}
	seen := make(map[string]struct{}, len(body.Roots))
	items := make([]bulkMutationItem, 0, len(body.Roots))
	for index, nodeID := range body.Roots {
		nodeID = strings.TrimSpace(nodeID)
		if nodeID == "" {
			s.handleError(w, r, files.NewError(files.CodeInvalid, "create archive", "", "every root requires an id"))
			return
		}
		if _, exists := seen[nodeID]; exists {
			s.handleError(w, r, files.NewError(files.CodeInvalid, "create archive", nodeID, "duplicate root"))
			return
		}
		seen[nodeID] = struct{}{}
		body.Roots[index] = nodeID
		items = append(items, bulkMutationItem{ID: nodeID})
	}
	if err := validateBulkRootsDoNotOverlap(r.Context(), s.runtime.Database.Reader(), items); err != nil {
		s.handleError(w, r, err)
		return
	}
	if supportUserID := strings.TrimSpace(r.URL.Query().Get("support_user")); supportUserID != "" {
		if _, err := s.validateSupportBrowse(r, supportUserID); err != nil {
			s.handleError(w, r, err)
			return
		}
	}
	entries, err := s.prepareArchive(r, body.Roots)
	if err != nil {
		s.handleError(w, r, err)
		return
	}
	filename := archiveDownloadName(body.Name)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filename}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	zw := zip.NewWriter(w)
	buffer := make([]byte, archiveCopyBuffer)
	for _, entry := range entries {
		if err := r.Context().Err(); err != nil {
			return
		}
		header := &zip.FileHeader{Name: entry.ArchivePath, Method: zip.Store, Modified: entry.Node.UpdatedAt.UTC()}
		if entry.Node.Kind == files.KindFolder {
			header.Name = strings.TrimSuffix(header.Name, "/") + "/"
			header.SetMode(0o755 | 0o040000)
			if _, err := zw.CreateHeader(header); err != nil {
				s.logger.Error("archive folder header failed", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID, "error", err)
				return
			}
			continue
		}
		resolved, err := s.runtime.Files.Content(r.Context(), principal(r).UserID, entry.Node.ID, "")
		if err != nil {
			s.logger.Warn("archive authorization changed during stream", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID, "error", err)
			return
		}
		reader, err := s.runtime.Storage.OpenBlob(resolved.StorageKey)
		if err != nil {
			s.logger.Error("archive blob open failed", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID, "error", err)
			return
		}
		header.UncompressedSize64 = uint64(resolved.Version.SizeBytes)
		writer, err := zw.CreateHeader(header)
		if err != nil {
			_ = reader.Close()
			s.logger.Error("archive file header failed", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID, "error", err)
			return
		}
		copied, copyErr := io.CopyBuffer(writer, io.LimitReader(reader, resolved.Version.SizeBytes+1), buffer)
		closeErr := reader.Close()
		if copyErr != nil || closeErr != nil || copied != resolved.Version.SizeBytes {
			s.logger.Error("archive file stream failed", "request_id", RequestID(r.Context()), "node_id", entry.Node.ID,
				"copied", copied, "expected", resolved.Version.SizeBytes, "error", errors.Join(copyErr, closeErr))
			return
		}
	}
	if err := zw.Close(); err != nil {
		s.logger.Error("archive finalize failed", "request_id", RequestID(r.Context()), "error", err)
	}
}

func (s *Server) prepareArchive(r *http.Request, roots []string) ([]archiveEntry, error) {
	actorID := principal(r).UserID
	usedPaths := make(map[string]struct{})
	entries := make([]archiveEntry, 0, len(roots))
	for _, rootID := range roots {
		root, err := s.runtime.Files.Get(r.Context(), actorID, rootID)
		if err != nil {
			return nil, err
		}
		if err := s.validateSupportNodeQuery(r, root); err != nil {
			return nil, err
		}
		if err := s.auditSupportRead(r, root.ID, "support_access.item_opened"); err != nil {
			return nil, err
		}
		rawNodes, err := collectArchiveTree(r.Context(), s.runtime.Database.Reader(), rootID)
		if err != nil {
			return nil, err
		}
		paths := make(map[string]string, len(rawNodes))
		for _, raw := range rawNodes {
			node, err := s.runtime.Files.Get(r.Context(), actorID, raw.ID)
			if err != nil {
				return nil, err
			}
			if err := s.validateSupportNodeQuery(r, node); err != nil {
				return nil, err
			}
			parentPath := ""
			if raw.ParentID.Valid && raw.ID != rootID {
				var ok bool
				parentPath, ok = paths[raw.ParentID.String]
				if !ok {
					return nil, files.NewError(files.CodeInvalidState, "create archive", raw.ID, "archive parent was not resolved")
				}
			}
			name := safeArchiveSegment(node.Name)
			if raw.ID == rootID && node.Name == "" {
				name = "Files"
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
				if _, err := s.runtime.Files.Content(r.Context(), actorID, node.ID, ""); err != nil {
					return nil, err
				}
				if err := s.auditSupportRead(r, node.ID, "support_access.content_downloaded"); err != nil {
					return nil, err
				}
			}
			entries = append(entries, archiveEntry{Node: node, ArchivePath: archivePath})
			if len(entries) > maxArchiveEntries {
				return nil, files.NewError(files.CodeItemLimit, "create archive", "", "archive would exceed 100000 entries")
			}
		}
	}
	return entries, nil
}

func collectArchiveTree(ctx context.Context, q database.Queryer, rootID string) ([]bulkNodeState, error) {
	rows, err := q.QueryContext(ctx, `WITH RECURSIVE tree(id, owner_id, parent_id, kind, name, name_key, revision, trashed_at, original_parent_id, depth) AS (
		SELECT id, owner_id, parent_id, kind, name, name_key, revision, trashed_at, original_parent_id, 0
		FROM nodes WHERE id = ? AND trashed_at IS NULL
		UNION ALL
		SELECT n.id, n.owner_id, n.parent_id, n.kind, n.name, n.name_key, n.revision, n.trashed_at, n.original_parent_id, t.depth + 1
		FROM nodes n JOIN tree t ON n.parent_id = t.id WHERE t.depth < 100 AND n.trashed_at IS NULL
	) SELECT id, owner_id, parent_id, kind, name, name_key, revision, trashed_at, original_parent_id
	FROM tree ORDER BY depth, name_key, id`, rootID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []bulkNodeState
	for rows.Next() {
		var node bulkNodeState
		if err := rows.Scan(&node.ID, &node.OwnerID, &node.ParentID, &node.Kind, &node.Name, &node.NameKey,
			&node.Revision, &node.TrashedAt, &node.OriginalParentID); err != nil {
			return nil, err
		}
		result = append(result, node)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, files.NewError(files.CodeNotFound, "create archive", rootID, "node not found")
	}
	return result, nil
}

func safeArchiveSegment(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == 0 || unicode.IsControl(r) {
			return '_'
		}
		return r
	}, value)
	value = strings.Trim(value, " .")
	if value == "" || value == "." || value == ".." {
		return "item"
	}
	return value
}

func uniqueArchivePath(candidate string, directory bool, used map[string]struct{}) (string, error) {
	candidate = strings.TrimPrefix(path.Clean("/"+candidate), "/")
	if candidate == "" || candidate == "." || strings.HasPrefix(candidate, "../") || len([]byte(candidate)) > 60_000 {
		return "", files.NewError(files.CodeInvalidName, "create archive", candidate, "archive path is unsafe or too long")
	}
	dir, base := path.Split(candidate)
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	for suffix := 0; suffix <= 10_000; suffix++ {
		value := candidate
		if suffix > 0 {
			value = path.Join(dir, fmt.Sprintf("%s (%d)%s", stem, suffix, ext))
		}
		key := strings.ToLower(strings.TrimSuffix(value, "/"))
		if _, exists := used[key]; exists {
			continue
		}
		used[key] = struct{}{}
		if directory {
			value = strings.TrimSuffix(value, "/") + "/"
		}
		return value, nil
	}
	return "", files.NewError(files.CodeConflict, "create archive", candidate, "too many archive name collisions")
}

func archiveDownloadName(value string) string {
	value = safeArchiveSegment(value)
	if value == "item" {
		value = "arca-files"
	}
	if !strings.EqualFold(path.Ext(value), ".zip") {
		value += ".zip"
	}
	return value
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
	replaceRevision := int64(0)
	if value := metadata["replace_revision"]; value != "" {
		replaceRevision, err = strconv.ParseInt(value, 10, 64)
		if err != nil || replaceRevision <= 0 {
			WriteProblem(w, r, http.StatusBadRequest, "invalid_replace_revision", "Invalid replacement revision", "replace_revision must be a positive base-10 integer.")
			return
		}
	}
	upload, err := s.runtime.Uploads.Create(r.Context(), uploads.CreateRequest{ActorID: p.UserID, ParentID: parentID, Name: metadata["filename"], ExpectedBytes: expected, ConflictMode: uploads.ConflictMode(metadata["conflict"]), ReplaceNodeID: metadata["replace_node_id"], ReplaceRevision: replaceRevision, ShareID: metadata["share_id"]})
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
