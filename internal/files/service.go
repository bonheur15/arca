package files

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"arca/internal/database"
	"github.com/google/uuid"
)

type Service struct {
	db    *database.DB
	now   func() time.Time
	newID func() (string, error)
}

type ServiceOptions struct {
	Now   func() time.Time
	NewID func() (string, error)
}

func NewService(db *database.DB, opts ServiceOptions) *Service {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	newID := opts.NewID
	if newID == nil {
		newID = func() (string, error) {
			id, err := uuid.NewV7()
			return id.String(), err
		}
	}
	return &Service{db: db, now: now, newID: newID}
}

func timeText(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTime(value string) (time.Time, error) { return time.Parse(time.RFC3339Nano, value) }

func nullableTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	t, err := parseTime(value.String)
	return &t, err
}

func (s *Service) CreateUserRoot(ctx context.Context, userID string) (Node, error) {
	const op = "create user root"
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return Node{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var existing sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT root_node_id FROM users WHERE id = ?", userID).Scan(&existing); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Node{}, NewError(CodeNotFound, op, userID, "user not found")
		}
		return Node{}, WrapError(CodeInvalid, op, userID, err)
	}
	if existing.Valid {
		node, err := getNodeQ(ctx, tx, existing.String, userID)
		if err != nil {
			return Node{}, err
		}
		_ = tx.Rollback(ctx)
		return node, nil
	}
	id, err := s.newID()
	if err != nil {
		return Node{}, fmt.Errorf("%s: generate UUIDv7: %w", op, err)
	}
	now := timeText(s.now())
	if _, err := tx.ExecContext(ctx, `INSERT INTO nodes
        (id, owner_id, parent_id, kind, name, name_key, created_by, created_at, updated_at)
        VALUES (?, ?, NULL, 'folder', '', '', ?, ?, ?)`, id, userID, userID, now, now); err != nil {
		return Node{}, mapConstraint(op, id, err)
	}
	result, err := tx.ExecContext(ctx, "UPDATE users SET root_node_id = ?, updated_at = ? WHERE id = ? AND root_node_id IS NULL", id, now, userID)
	if err != nil {
		return Node{}, WrapError(CodeInvalid, op, userID, err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return Node{}, NewError(CodeConflict, op, userID, "root was initialized concurrently")
	}
	if err := tx.Commit(ctx); err != nil {
		return Node{}, err
	}
	return s.Get(ctx, userID, id)
}

func (s *Service) Get(ctx context.Context, actorID, nodeID string) (Node, error) {
	access, err := Authorize(ctx, s.db.Reader(), actorID, nodeID, ActionRead, s.now())
	if err != nil {
		return Node{}, err
	}
	node, err := getNodeQ(ctx, s.db.Reader(), nodeID, actorID)
	if err != nil {
		return Node{}, err
	}
	node.Capabilities = CapabilitiesFor(access, node.ParentID == nil)
	return node, nil
}

func (s *Service) List(ctx context.Context, actorID, parentID string, options ListOptions) (NodePage, error) {
	access, err := Authorize(ctx, s.db.Reader(), actorID, parentID, ActionRead, s.now())
	if err != nil {
		return NodePage{}, err
	}
	parent, err := getNodeQ(ctx, s.db.Reader(), parentID, actorID)
	if err != nil {
		return NodePage{}, err
	}
	if parent.Kind != KindFolder {
		return NodePage{}, NewError(CodeInvalid, "list folder", parentID, "parent is not a folder")
	}
	limit := clampLimit(options.Limit)
	nameKey, cursorID, err := decodeListCursor(options.Cursor)
	if err != nil {
		return NodePage{}, err
	}
	rows, err := s.db.Reader().QueryContext(ctx, nodeSelect+`
        WHERE n.parent_id = ? AND n.trashed_at IS NULL
          AND (? = '' OR n.name_key > ? OR (n.name_key = ? AND n.id > ?))
        ORDER BY n.name_key, n.id LIMIT ?`, actorID, parentID, nameKey, nameKey, nameKey, cursorID, limit+1)
	if err != nil {
		return NodePage{}, WrapError(CodeInvalid, "list folder", parentID, err)
	}
	defer rows.Close()
	page, err := scanNodePage(rows, limit, access)
	if err != nil {
		return NodePage{}, err
	}
	return page, nil
}

func (s *Service) CreateFolder(ctx context.Context, actorID, parentID, name string) (Node, error) {
	const op = "create folder"
	display, key, err := NormalizeName(name)
	if err != nil {
		return Node{}, err
	}
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return Node{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	access, err := Authorize(ctx, tx, actorID, parentID, ActionCreateChild, s.now())
	if err != nil {
		return Node{}, err
	}
	parent, err := getNodeQ(ctx, tx, parentID, actorID)
	if err != nil {
		return Node{}, err
	}
	if parent.Kind != KindFolder {
		return Node{}, NewError(CodeInvalid, op, parentID, "parent is not a folder")
	}
	if err := checkItemLimit(ctx, tx, access.OwnerID, 1); err != nil {
		return Node{}, err
	}
	id, err := s.newID()
	if err != nil {
		return Node{}, fmt.Errorf("%s: generate UUIDv7: %w", op, err)
	}
	now := timeText(s.now())
	_, err = tx.ExecContext(ctx, `INSERT INTO nodes
        (id, owner_id, parent_id, kind, name, name_key, created_by, created_at, updated_at)
        VALUES (?, ?, ?, 'folder', ?, ?, ?, ?, ?)`, id, access.OwnerID, parentID, display, key, actorID, now, now)
	if err != nil {
		return Node{}, mapConstraint(op, parentID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Node{}, err
	}
	return s.Get(ctx, actorID, id)
}

func (s *Service) Rename(ctx context.Context, actorID, nodeID, name string, expectedRevision int64) (Node, error) {
	const op = "rename node"
	if expectedRevision <= 0 {
		return Node{}, NewError(CodePreconditionRequired, op, nodeID, "a positive revision is required")
	}
	display, key, err := NormalizeName(name)
	if err != nil {
		return Node{}, err
	}
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return Node{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := Authorize(ctx, tx, actorID, nodeID, ActionRename, s.now()); err != nil {
		return Node{}, err
	}
	node, err := getNodeQ(ctx, tx, nodeID, actorID)
	if err != nil {
		return Node{}, err
	}
	if node.ParentID == nil {
		return Node{}, NewError(CodeForbidden, op, nodeID, "root cannot be renamed")
	}
	result, err := tx.ExecContext(ctx, `UPDATE nodes SET name = ?, name_key = ?, revision = revision + 1, updated_at = ?
        WHERE id = ? AND revision = ?`, display, key, timeText(s.now()), nodeID, expectedRevision)
	if err != nil {
		return Node{}, mapConstraint(op, nodeID, err)
	}
	if err := requireAffected(result, op, nodeID); err != nil {
		return Node{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Node{}, err
	}
	return s.Get(ctx, actorID, nodeID)
}

func (s *Service) Move(ctx context.Context, actorID, nodeID, destinationID string, expectedRevision int64) (Node, error) {
	const op = "move node"
	if expectedRevision <= 0 {
		return Node{}, NewError(CodePreconditionRequired, op, nodeID, "a positive revision is required")
	}
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return Node{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	sourceAccess, err := Authorize(ctx, tx, actorID, nodeID, ActionMove, s.now())
	if err != nil {
		return Node{}, err
	}
	destinationAccess, err := Authorize(ctx, tx, actorID, destinationID, ActionCreateChild, s.now())
	if err != nil {
		return Node{}, err
	}
	if sourceAccess.OwnerID != destinationAccess.OwnerID {
		return Node{}, NewError(CodeForbidden, op, nodeID, "cannot move nodes across owners")
	}
	source, err := getNodeQ(ctx, tx, nodeID, actorID)
	if err != nil {
		return Node{}, err
	}
	destination, err := getNodeQ(ctx, tx, destinationID, actorID)
	if err != nil {
		return Node{}, err
	}
	if source.ParentID == nil {
		return Node{}, NewError(CodeForbidden, op, nodeID, "root cannot be moved")
	}
	if destination.Kind != KindFolder {
		return Node{}, NewError(CodeInvalid, op, destinationID, "destination is not a folder")
	}
	if source.Kind == KindFolder {
		var cycle int
		err := tx.QueryRowContext(ctx, `WITH RECURSIVE descendants(id, depth) AS (
            SELECT id, 0 FROM nodes WHERE id = ?
            UNION ALL SELECT n.id, d.depth + 1 FROM nodes n JOIN descendants d ON n.parent_id = d.id WHERE d.depth < 100
        ) SELECT 1 FROM descendants WHERE id = ? LIMIT 1`, nodeID, destinationID).Scan(&cycle)
		if err == nil {
			return Node{}, NewError(CodeCycle, op, nodeID, "folder cannot be moved into itself or a descendant")
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return Node{}, WrapError(CodeInvalid, op, nodeID, err)
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE nodes SET parent_id = ?, revision = revision + 1, updated_at = ?
        WHERE id = ? AND revision = ?`, destinationID, timeText(s.now()), nodeID, expectedRevision)
	if err != nil {
		return Node{}, mapConstraint(op, nodeID, err)
	}
	if err := requireAffected(result, op, nodeID); err != nil {
		return Node{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Node{}, err
	}
	return s.Get(ctx, actorID, nodeID)
}

func (s *Service) Trash(ctx context.Context, actorID, nodeID string, expectedRevision int64) (Node, error) {
	const op = "trash node"
	if expectedRevision <= 0 {
		return Node{}, NewError(CodePreconditionRequired, op, nodeID, "a positive revision is required")
	}
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return Node{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := Authorize(ctx, tx, actorID, nodeID, ActionTrash, s.now()); err != nil {
		return Node{}, err
	}
	node, err := getNodeQ(ctx, tx, nodeID, actorID)
	if err != nil {
		return Node{}, err
	}
	if node.ParentID == nil {
		return Node{}, NewError(CodeForbidden, op, nodeID, "root cannot be trashed")
	}
	now := timeText(s.now())
	result, err := tx.ExecContext(ctx, `UPDATE nodes
        SET trashed_at = ?, original_parent_id = parent_id, revision = revision + 1, updated_at = ?
        WHERE id = ? AND revision = ? AND trashed_at IS NULL`, now, now, nodeID, expectedRevision)
	if err != nil {
		return Node{}, mapConstraint(op, nodeID, err)
	}
	if err := requireAffected(result, op, nodeID); err != nil {
		return Node{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Node{}, err
	}
	return s.getDirect(ctx, actorID, nodeID)
}

func (s *Service) Restore(ctx context.Context, actorID, nodeID string, expectedRevision int64) (Node, error) {
	const op = "restore node"
	if expectedRevision <= 0 {
		return Node{}, NewError(CodePreconditionRequired, op, nodeID, "a positive revision is required")
	}
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return Node{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	node, err := getNodeQ(ctx, tx, nodeID, actorID)
	if err != nil {
		return Node{}, err
	}
	if node.OwnerID != actorID || node.TrashedAt == nil {
		return Node{}, NewError(CodeForbidden, op, nodeID, "only the owner can restore a trash root")
	}
	var rootID string
	if err := tx.QueryRowContext(ctx, "SELECT root_node_id FROM users WHERE id = ?", actorID).Scan(&rootID); err != nil {
		return Node{}, WrapError(CodeInvalid, op, nodeID, err)
	}
	destinationID := rootID
	if node.OriginalParentID != nil {
		var valid int
		err := tx.QueryRowContext(ctx, `WITH RECURSIVE ancestors(id, parent_id, trashed_at, depth) AS (
            SELECT id, parent_id, trashed_at, 0 FROM nodes WHERE id = ? AND kind = 'folder'
            UNION ALL SELECT n.id, n.parent_id, n.trashed_at, a.depth + 1 FROM nodes n JOIN ancestors a ON n.id = a.parent_id WHERE a.depth < 100
        ) SELECT 1 WHERE EXISTS (SELECT 1 FROM ancestors) AND NOT EXISTS (SELECT 1 FROM ancestors WHERE trashed_at IS NOT NULL)`, *node.OriginalParentID).Scan(&valid)
		if err == nil {
			destinationID = *node.OriginalParentID
		} else if !errors.Is(err, sql.ErrNoRows) {
			return Node{}, WrapError(CodeInvalid, op, nodeID, err)
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE nodes SET parent_id = ?, trashed_at = NULL,
        original_parent_id = NULL, revision = revision + 1, updated_at = ?
        WHERE id = ? AND owner_id = ? AND revision = ? AND trashed_at IS NOT NULL`,
		destinationID, timeText(s.now()), nodeID, actorID, expectedRevision)
	if err != nil {
		return Node{}, mapConstraint(op, nodeID, err)
	}
	if err := requireAffected(result, op, nodeID); err != nil {
		return Node{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Node{}, err
	}
	return s.Get(ctx, actorID, nodeID)
}

func (s *Service) ListTrash(ctx context.Context, actorID string, options ListOptions) (NodePage, error) {
	limit := clampLimit(options.Limit)
	offset, err := decodeOffsetCursor(options.Cursor)
	if err != nil {
		return NodePage{}, err
	}
	rows, err := s.db.Reader().QueryContext(ctx, nodeSelect+`
        JOIN users owner ON owner.id = n.owner_id
        WHERE n.owner_id = ? AND n.trashed_at IS NOT NULL AND owner.state IN ('active', 'over_quota')
        ORDER BY n.trashed_at DESC, n.id LIMIT ? OFFSET ?`, actorID, actorID, limit+1, offset)
	if err != nil {
		return NodePage{}, WrapError(CodeInvalid, "list trash", actorID, err)
	}
	defer rows.Close()
	items, err := scanNodes(rows, actorID, Access{ActorID: actorID, OwnerID: actorID, Owner: true})
	if err != nil {
		return NodePage{}, err
	}
	page := NodePage{Items: items}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		page.NextCursor = encodeOffsetCursor(offset + limit)
	}
	return page, nil
}

func requireAffected(result sql.Result, op, resource string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return WrapError(CodeInvalid, op, resource, err)
	}
	if rows != 1 {
		return NewError(CodeRevisionMismatch, op, resource, "resource changed since it was read")
	}
	return nil
}

func checkItemLimit(ctx context.Context, q database.Queryer, ownerID string, additional int64) error {
	var count, maximum int64
	err := q.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM nodes WHERE owner_id = ?), p.max_items
        FROM user_policies p WHERE p.user_id = ?`, ownerID, ownerID).Scan(&count, &maximum)
	if errors.Is(err, sql.ErrNoRows) {
		return NewError(CodeInvalid, "check item limit", ownerID, "user policy is missing")
	}
	if err != nil {
		return WrapError(CodeInvalid, "check item limit", ownerID, err)
	}
	if count+additional > maximum {
		return NewError(CodeItemLimit, "check item limit", ownerID, "item limit would be exceeded")
	}
	return nil
}

const nodeSelect = `SELECT n.id, n.owner_id, n.parent_id, n.kind, n.name, n.mime_type,
    n.size_bytes, n.current_version_id, n.revision, n.created_by, n.trashed_at,
    n.original_parent_id, n.created_at, n.updated_at,
    CASE WHEN f.node_id IS NULL THEN 0 ELSE 1 END
    FROM nodes n LEFT JOIN favorites f ON f.node_id = n.id AND f.user_id = ? `

func getNodeQ(ctx context.Context, q database.Queryer, nodeID, favoriteUserID string) (Node, error) {
	row := q.QueryRowContext(ctx, nodeSelect+" WHERE n.id = ?", favoriteUserID, nodeID)
	node, err := scanNode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, NewError(CodeNotFound, "get node", nodeID, "node not found")
	}
	if err != nil {
		return Node{}, WrapError(CodeInvalid, "get node", nodeID, err)
	}
	return node, nil
}

func (s *Service) getDirect(ctx context.Context, actorID, nodeID string) (Node, error) {
	node, err := getNodeQ(ctx, s.db.Reader(), nodeID, actorID)
	if err != nil {
		return Node{}, err
	}
	if node.OwnerID != actorID {
		return Node{}, NewError(CodeForbidden, "get trashed node", nodeID, "owner-only")
	}
	node.Capabilities = CapabilitiesFor(Access{ActorID: actorID, OwnerID: actorID, NodeID: nodeID, Owner: true}, false)
	return node, nil
}

type rowScanner interface{ Scan(...any) error }

func scanNode(row rowScanner) (Node, error) {
	var n Node
	var parent, mime, current, trashed, original sql.NullString
	var created, updated string
	var favorite int
	err := row.Scan(&n.ID, &n.OwnerID, &parent, &n.Kind, &n.Name, &mime, &n.SizeBytes,
		&current, &n.Revision, &n.CreatedBy, &trashed, &original, &created, &updated, &favorite)
	if err != nil {
		return Node{}, err
	}
	if parent.Valid {
		n.ParentID = &parent.String
	}
	if mime.Valid {
		n.MIMEType = &mime.String
	}
	if current.Valid {
		n.CurrentVersionID = &current.String
	}
	if original.Valid {
		n.OriginalParentID = &original.String
	}
	var parseErr error
	n.TrashedAt, parseErr = nullableTime(trashed)
	if parseErr != nil {
		return Node{}, parseErr
	}
	n.CreatedAt, parseErr = parseTime(created)
	if parseErr != nil {
		return Node{}, parseErr
	}
	n.UpdatedAt, parseErr = parseTime(updated)
	if parseErr != nil {
		return Node{}, parseErr
	}
	n.Favorite = favorite == 1
	return n, nil
}

func scanNodes(rows *sql.Rows, favoriteUserID string, access Access) ([]Node, error) {
	var items []Node
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		access.NodeID = node.ID
		node.Capabilities = CapabilitiesFor(access, node.ParentID == nil)
		items = append(items, node)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func scanNodePage(rows *sql.Rows, limit int, access Access) (NodePage, error) {
	items, err := scanNodes(rows, access.ActorID, access)
	if err != nil {
		return NodePage{}, err
	}
	page := NodePage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		last := page.Items[len(page.Items)-1]
		_, key, _ := NormalizeName(last.Name)
		page.NextCursor = encodeListCursor(key, last.ID)
	}
	return page, nil
}

func clampLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 200 {
		return 200
	}
	return limit
}

type listCursor struct {
	NameKey string `json:"n"`
	ID      string `json:"i"`
}

func encodeListCursor(nameKey, id string) string {
	b, _ := json.Marshal(listCursor{NameKey: nameKey, ID: id})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeListCursor(cursor string) (string, string, error) {
	if cursor == "" {
		return "", "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", "", NewError(CodeInvalid, "decode cursor", "", "invalid cursor")
	}
	var value listCursor
	if err := json.Unmarshal(b, &value); err != nil || value.NameKey == "" || value.ID == "" {
		return "", "", NewError(CodeInvalid, "decode cursor", "", "invalid cursor")
	}
	return value.NameKey, value.ID, nil
}

func encodeOffsetCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

func decodeOffsetCursor(cursor string) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, NewError(CodeInvalid, "decode cursor", "", "invalid cursor")
	}
	offset, err := strconv.Atoi(string(b))
	if err != nil || offset < 0 {
		return 0, NewError(CodeInvalid, "decode cursor", "", "invalid cursor")
	}
	return offset, nil
}

func ftsExpression(query string) string {
	fields := strings.Fields(query)
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.ReplaceAll(field, `"`, `""`)
		parts = append(parts, `"`+field+`"*`)
	}
	return strings.Join(parts, " AND ")
}
