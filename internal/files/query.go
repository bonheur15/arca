package files

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

func (s *Service) SetFavorite(ctx context.Context, actorID, nodeID string, favorite bool) error {
	if _, err := Authorize(ctx, s.db.Reader(), actorID, nodeID, ActionRead, s.now()); err != nil {
		return err
	}
	if favorite {
		_, err := s.db.Writer().ExecContext(ctx, `INSERT INTO favorites(user_id, node_id, created_at)
            VALUES (?, ?, ?) ON CONFLICT(user_id, node_id) DO NOTHING`, actorID, nodeID, timeText(s.now()))
		return mapConstraint("favorite node", nodeID, err)
	}
	_, err := s.db.Writer().ExecContext(ctx, "DELETE FROM favorites WHERE user_id = ? AND node_id = ?", actorID, nodeID)
	if err != nil {
		return WrapError(CodeInvalid, "unfavorite node", nodeID, err)
	}
	return nil
}

func (s *Service) ListFavorites(ctx context.Context, actorID string, options ListOptions) (NodePage, error) {
	limit := clampLimit(options.Limit)
	offset, err := decodeOffsetCursor(options.Cursor)
	if err != nil {
		return NodePage{}, err
	}
	rows, err := s.db.Reader().QueryContext(ctx, nodeSelect+`
        JOIN favorites mine ON mine.node_id = n.id AND mine.user_id = ?
        WHERE n.trashed_at IS NULL ORDER BY mine.created_at DESC, n.id LIMIT ? OFFSET ?`,
		actorID, actorID, limit*4+1, offset)
	if err != nil {
		return NodePage{}, WrapError(CodeInvalid, "list favorites", actorID, err)
	}
	defer rows.Close()
	var candidates []Node
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return NodePage{}, err
		}
		candidates = append(candidates, node)
	}
	if err := rows.Err(); err != nil {
		return NodePage{}, err
	}
	if err := rows.Close(); err != nil {
		return NodePage{}, err
	}
	var items []Node
	for _, node := range candidates {
		access, err := Authorize(ctx, s.db.Reader(), actorID, node.ID, ActionRead, s.now())
		if err != nil {
			if ErrorCodeOf(err) == CodeForbidden || ErrorCodeOf(err) == CodeNotFound {
				continue
			}
			return NodePage{}, err
		}
		node.Capabilities = CapabilitiesFor(access, node.ParentID == nil)
		items = append(items, node)
		if len(items) > limit {
			break
		}
	}
	page := NodePage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = encodeOffsetCursor(offset + limit)
	}
	return page, nil
}

func (s *Service) Search(ctx context.Context, actorID string, options SearchOptions) (NodePage, error) {
	query := ftsExpression(options.Query)
	if query == "" {
		return NodePage{}, NewError(CodeInvalid, "search nodes", "", "query is required")
	}
	limit := clampLimit(options.Limit)
	offset, err := decodeOffsetCursor(options.Cursor)
	if err != nil {
		return NodePage{}, err
	}
	rows, err := s.db.Reader().QueryContext(ctx, nodeSelect+`
        JOIN node_search search ON search.node_id = n.id
        WHERE node_search MATCH ? AND n.trashed_at IS NULL
          AND (? = '' OR n.kind = ?) AND (? = '' OR n.mime_type = ?)
        ORDER BY bm25(node_search), n.name_key, n.id LIMIT ? OFFSET ?`,
		actorID, query, string(options.Kind), string(options.Kind), options.MIMEType, options.MIMEType, limit*8+1, offset)
	if err != nil {
		return NodePage{}, WrapError(CodeInvalid, "search nodes", actorID, err)
	}
	defer rows.Close()
	var candidates []Node
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return NodePage{}, err
		}
		candidates = append(candidates, node)
	}
	if err := rows.Err(); err != nil {
		return NodePage{}, err
	}
	if err := rows.Close(); err != nil {
		return NodePage{}, err
	}
	var items []Node
	for _, node := range candidates {
		access, err := Authorize(ctx, s.db.Reader(), actorID, node.ID, ActionRead, s.now())
		if err != nil {
			if ErrorCodeOf(err) == CodeForbidden || ErrorCodeOf(err) == CodeNotFound {
				continue
			}
			return NodePage{}, err
		}
		node.Capabilities = CapabilitiesFor(access, node.ParentID == nil)
		items = append(items, node)
		if len(items) > limit {
			break
		}
	}
	page := NodePage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = encodeOffsetCursor(offset + limit)
	}
	return page, nil
}

func (s *Service) ListVersions(ctx context.Context, actorID, nodeID string) ([]FileVersion, error) {
	if _, err := Authorize(ctx, s.db.Reader(), actorID, nodeID, ActionRead, s.now()); err != nil {
		return nil, err
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, node_id, blob_id, sequence, size_bytes,
        sha256, mime_type, created_by, created_at FROM file_versions WHERE node_id = ? ORDER BY sequence DESC`, nodeID)
	if err != nil {
		return nil, WrapError(CodeInvalid, "list file versions", nodeID, err)
	}
	defer rows.Close()
	var versions []FileVersion
	for rows.Next() {
		version, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	return versions, rows.Err()
}

func (s *Service) Content(ctx context.Context, actorID, nodeID, versionID string) (Content, error) {
	if _, err := Authorize(ctx, s.db.Reader(), actorID, nodeID, ActionRead, s.now()); err != nil {
		return Content{}, err
	}
	node, err := getNodeQ(ctx, s.db.Reader(), nodeID, actorID)
	if err != nil {
		return Content{}, err
	}
	if node.Kind != KindFile {
		return Content{}, NewError(CodeInvalid, "resolve file content", nodeID, "node is not a file")
	}
	if versionID == "" && node.CurrentVersionID != nil {
		versionID = *node.CurrentVersionID
	}
	var content Content
	content.Node = node
	var created string
	err = s.db.Reader().QueryRowContext(ctx, `SELECT v.id, v.node_id, v.blob_id, v.sequence, v.size_bytes,
        v.sha256, v.mime_type, v.created_by, v.created_at, b.storage_key, b.state
        FROM file_versions v JOIN blobs b ON b.id = v.blob_id
        WHERE v.node_id = ? AND v.id = ? AND b.state = 'ready'`, nodeID, versionID).Scan(
		&content.Version.ID, &content.Version.NodeID, &content.Version.BlobID, &content.Version.Sequence,
		&content.Version.SizeBytes, &content.Version.SHA256, &content.Version.MIMEType,
		&content.Version.CreatedBy, &created, &content.StorageKey, &content.BlobState)
	if errors.Is(err, sql.ErrNoRows) {
		return Content{}, NewError(CodeNotFound, "resolve file content", versionID, "version not found")
	}
	if err != nil {
		return Content{}, WrapError(CodeInvalid, "resolve file content", versionID, err)
	}
	content.Version.CreatedAt, err = parseTime(created)
	if err != nil {
		return Content{}, err
	}
	return content, nil
}

func (s *Service) RestoreVersion(ctx context.Context, actorID, nodeID, versionID string, expectedRevision int64) (FileVersion, error) {
	const op = "restore file version"
	if expectedRevision <= 0 {
		return FileVersion{}, NewError(CodePreconditionRequired, op, nodeID, "a positive revision is required")
	}
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return FileVersion{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	access, err := Authorize(ctx, tx, actorID, nodeID, ActionRestore, s.now())
	if err != nil {
		return FileVersion{}, err
	}
	if !access.Owner {
		return FileVersion{}, NewError(CodeForbidden, op, nodeID, "version restore is owner-only")
	}
	node, err := getNodeQ(ctx, tx, nodeID, actorID)
	if err != nil {
		return FileVersion{}, err
	}
	if node.Kind != KindFile {
		return FileVersion{}, NewError(CodeInvalid, op, nodeID, "node is not a file")
	}
	var source FileVersion
	var created string
	err = tx.QueryRowContext(ctx, `SELECT id, node_id, blob_id, sequence, size_bytes, sha256, mime_type, created_by, created_at
        FROM file_versions WHERE node_id = ? AND id = ?`, nodeID, versionID).Scan(&source.ID, &source.NodeID,
		&source.BlobID, &source.Sequence, &source.SizeBytes, &source.SHA256, &source.MIMEType, &source.CreatedBy, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return FileVersion{}, NewError(CodeNotFound, op, versionID, "version not found")
	}
	if err != nil {
		return FileVersion{}, WrapError(CodeInvalid, op, versionID, err)
	}
	newID, err := s.newID()
	if err != nil {
		return FileVersion{}, err
	}
	var sequence int64
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(sequence), 0) + 1 FROM file_versions WHERE node_id = ?", nodeID).Scan(&sequence); err != nil {
		return FileVersion{}, err
	}
	now := timeText(s.now())
	if _, err := tx.ExecContext(ctx, "UPDATE blobs SET ref_count = ref_count + 1 WHERE id = ? AND state = 'ready'", source.BlobID); err != nil {
		return FileVersion{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO file_versions
        (id, node_id, blob_id, sequence, size_bytes, sha256, mime_type, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, newID, nodeID, source.BlobID, sequence, source.SizeBytes, source.SHA256, source.MIMEType, actorID, now); err != nil {
		return FileVersion{}, mapConstraint(op, versionID, err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE nodes SET current_version_id = ?, size_bytes = ?, mime_type = ?,
        revision = revision + 1, updated_at = ? WHERE id = ? AND revision = ?`, newID, source.SizeBytes, source.MIMEType, now, nodeID, expectedRevision)
	if err != nil {
		return FileVersion{}, err
	}
	if err := requireAffected(result, op, nodeID); err != nil {
		return FileVersion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return FileVersion{}, err
	}
	return FileVersion{ID: newID, NodeID: nodeID, BlobID: source.BlobID, Sequence: sequence, SizeBytes: source.SizeBytes,
		SHA256: source.SHA256, MIMEType: source.MIMEType, CreatedBy: actorID, CreatedAt: s.now().UTC()}, nil
}

func scanVersion(row interface{ Scan(...any) error }) (FileVersion, error) {
	var v FileVersion
	var created string
	if err := row.Scan(&v.ID, &v.NodeID, &v.BlobID, &v.Sequence, &v.SizeBytes, &v.SHA256, &v.MIMEType, &v.CreatedBy, &created); err != nil {
		return FileVersion{}, err
	}
	var err error
	v.CreatedAt, err = parseTime(created)
	return v, err
}

func (s *Service) Purge(ctx context.Context, actorID, nodeID string, expectedRevision int64) (PurgeResult, error) {
	const op = "purge node"
	if expectedRevision <= 0 {
		return PurgeResult{}, NewError(CodePreconditionRequired, op, nodeID, "a positive revision is required")
	}
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return PurgeResult{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	node, err := getNodeQ(ctx, tx, nodeID, actorID)
	if err != nil {
		return PurgeResult{}, err
	}
	if node.OwnerID != actorID || node.TrashedAt == nil || node.ParentID == nil {
		return PurgeResult{}, NewError(CodeForbidden, op, nodeID, "only an owner may purge a trash root")
	}
	if node.Revision != expectedRevision {
		return PurgeResult{}, NewError(CodeRevisionMismatch, op, nodeID, "resource changed since it was read")
	}
	var pending int
	err = tx.QueryRowContext(ctx, `WITH RECURSIVE tree(id) AS (
        SELECT id FROM nodes WHERE id = ? UNION ALL SELECT n.id FROM nodes n JOIN tree t ON n.parent_id = t.id
    ) SELECT COUNT(*) FROM uploads
       WHERE (parent_id IN (SELECT id FROM tree) OR replace_node_id IN (SELECT id FROM tree))
         AND state IN ('pending', 'finalizing')`, nodeID).Scan(&pending)
	if err != nil {
		return PurgeResult{}, err
	}
	if pending != 0 {
		return PurgeResult{}, NewError(CodeConflict, op, nodeID, "tree has active uploads")
	}

	rows, err := tx.QueryContext(ctx, `WITH RECURSIVE tree(id, depth) AS (
        SELECT id, 0 FROM nodes WHERE id = ? UNION ALL SELECT n.id, t.depth + 1 FROM nodes n JOIN tree t ON n.parent_id = t.id WHERE t.depth < 100
    ) SELECT id, depth FROM tree ORDER BY depth DESC`, nodeID)
	if err != nil {
		return PurgeResult{}, err
	}
	type treeNode struct {
		id    string
		depth int
	}
	var tree []treeNode
	for rows.Next() {
		var item treeNode
		if err := rows.Scan(&item.id, &item.depth); err != nil {
			rows.Close()
			return PurgeResult{}, err
		}
		tree = append(tree, item)
	}
	if err := rows.Close(); err != nil {
		return PurgeResult{}, err
	}
	if len(tree) == 0 {
		return PurgeResult{}, NewError(CodeNotFound, op, nodeID, "node not found")
	}

	counts := make(map[string]int64)
	for _, item := range tree {
		versionRows, err := tx.QueryContext(ctx, "SELECT blob_id, COUNT(*) FROM file_versions WHERE node_id = ? GROUP BY blob_id", item.id)
		if err != nil {
			return PurgeResult{}, err
		}
		for versionRows.Next() {
			var blob string
			var count int64
			if err := versionRows.Scan(&blob, &count); err != nil {
				versionRows.Close()
				return PurgeResult{}, err
			}
			counts[blob] += count
		}
		if err := versionRows.Close(); err != nil {
			return PurgeResult{}, err
		}
	}
	result := PurgeResult{NodesDeleted: int64(len(tree))}
	deleteAfter := timeText(s.now().Add(24 * time.Hour))
	for blobID, count := range counts {
		result.VersionsDeleted += count
		res, err := tx.ExecContext(ctx, `UPDATE blobs SET ref_count = ref_count - ?,
            state = CASE WHEN ref_count <= ? THEN 'deleting' ELSE state END,
            delete_after = CASE WHEN ref_count <= ? THEN ? ELSE delete_after END
            WHERE id = ? AND ref_count >= ?`, count, count, count, deleteAfter, blobID, count)
		if err != nil {
			return PurgeResult{}, err
		}
		if affected, _ := res.RowsAffected(); affected != 1 {
			return PurgeResult{}, NewError(CodeInvalidState, op, blobID, "blob reference count is inconsistent")
		}
		var state string
		if err := tx.QueryRowContext(ctx, "SELECT state FROM blobs WHERE id = ?", blobID).Scan(&state); err != nil {
			return PurgeResult{}, err
		}
		if state == "deleting" {
			result.BlobsQueued++
		}
	}
	for _, item := range tree {
		if _, err := tx.ExecContext(ctx, `DELETE FROM uploads
            WHERE (parent_id = ? OR replace_node_id = ?) AND state IN ('completed', 'cancelled', 'expired', 'failed')`, item.id, item.id); err != nil {
			return PurgeResult{}, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM file_versions WHERE node_id = ?", item.id); err != nil {
			return PurgeResult{}, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM share_roots WHERE node_id = ?", item.id); err != nil {
			return PurgeResult{}, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM public_share_roots WHERE node_id = ?", item.id); err != nil {
			return PurgeResult{}, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM nodes WHERE id = ?", item.id); err != nil {
			return PurgeResult{}, mapConstraint(op, item.id, err)
		}
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM shares WHERE NOT EXISTS (SELECT 1 FROM share_roots WHERE share_id = shares.id)"); err != nil {
		return PurgeResult{}, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM public_shares WHERE NOT EXISTS (SELECT 1 FROM public_share_roots WHERE public_share_id = public_shares.id)"); err != nil {
		return PurgeResult{}, err
	}
	jobID, err := uuid.NewV7()
	if err != nil {
		return PurgeResult{}, err
	}
	now := timeText(s.now())
	if _, err := tx.ExecContext(ctx, `INSERT INTO jobs(id, kind, payload, state, run_after, created_at, updated_at)
        VALUES (?, 'blob_gc', '{}', 'queued', ?, ?, ?)`, jobID.String(), deleteAfter, now, now); err != nil {
		return PurgeResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PurgeResult{}, err
	}
	return result, nil
}

func (s *Service) Recent(ctx context.Context, actorID string, options ListOptions) (NodePage, error) {
	limit := clampLimit(options.Limit)
	offset, err := decodeOffsetCursor(options.Cursor)
	if err != nil {
		return NodePage{}, err
	}
	rows, err := s.db.Reader().QueryContext(ctx, nodeSelect+`
        WHERE n.owner_id = ? AND n.parent_id IS NOT NULL AND n.trashed_at IS NULL
          AND NOT EXISTS (WITH RECURSIVE ancestors(id, parent_id, trashed_at) AS (
            SELECT id, parent_id, trashed_at FROM nodes WHERE id = n.id
            UNION ALL SELECT p.id, p.parent_id, p.trashed_at FROM nodes p JOIN ancestors a ON p.id = a.parent_id
          ) SELECT 1 FROM ancestors WHERE trashed_at IS NOT NULL)
        ORDER BY n.updated_at DESC, n.id LIMIT ? OFFSET ?`, actorID, actorID, limit+1, offset)
	if err != nil {
		return NodePage{}, fmt.Errorf("list recent: %w", err)
	}
	defer rows.Close()
	items, err := scanNodes(rows, actorID, Access{ActorID: actorID, OwnerID: actorID, Owner: true})
	if err != nil {
		return NodePage{}, err
	}
	page := NodePage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = encodeOffsetCursor(offset + limit)
	}
	return page, nil
}
