package files

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type CopyRequest struct {
	ActorID       string
	NodeID        string
	DestinationID string
	Name          string
	KeepBoth      bool
}

type copyNode struct {
	id, parentID, kind, name, nameKey string
	mime                              sql.NullString
	size                              int64
	currentVersion                    sql.NullString
	depth                             int
}

// Copy creates an independent metadata tree within one owner while reusing
// immutable blobs. Cross-owner copies require a physical blob copy and are
// intentionally rejected by this method.
func (s *Service) Copy(ctx context.Context, request CopyRequest) (Node, error) {
	const op = "copy node"
	tx, err := s.db.BeginImmediate(ctx)
	if err != nil {
		return Node{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	sourceAccess, err := Authorize(ctx, tx, request.ActorID, request.NodeID, ActionRead, s.now())
	if err != nil {
		return Node{}, err
	}
	destinationAccess, err := Authorize(ctx, tx, request.ActorID, request.DestinationID, ActionCreateChild, s.now())
	if err != nil {
		return Node{}, err
	}
	if sourceAccess.OwnerID != destinationAccess.OwnerID {
		return Node{}, NewError(CodeCrossOwnerCopy, op, request.NodeID, "cross-owner copies require a new recipient-owned blob")
	}
	destination, err := getNodeQ(ctx, tx, request.DestinationID, request.ActorID)
	if err != nil {
		return Node{}, err
	}
	if destination.Kind != KindFolder {
		return Node{}, NewError(CodeInvalid, op, request.DestinationID, "destination is not a folder")
	}
	source, err := getNodeQ(ctx, tx, request.NodeID, request.ActorID)
	if err != nil {
		return Node{}, err
	}
	if source.ParentID == nil {
		return Node{}, NewError(CodeForbidden, op, request.NodeID, "the hidden user root cannot be copied")
	}

	rows, err := tx.QueryContext(ctx, `WITH RECURSIVE tree(id, parent_id, kind, name, name_key, mime_type,
		size_bytes, current_version_id, depth) AS (
		SELECT id, parent_id, kind, name, name_key, mime_type, size_bytes, current_version_id, 0
		FROM nodes WHERE id = ? AND trashed_at IS NULL
		UNION ALL
		SELECT n.id, n.parent_id, n.kind, n.name, n.name_key, n.mime_type, n.size_bytes, n.current_version_id, tree.depth + 1
		FROM nodes n JOIN tree ON n.parent_id = tree.id
		WHERE n.trashed_at IS NULL AND tree.depth < 100
	) SELECT id, parent_id, kind, name, name_key, mime_type, size_bytes, current_version_id, depth
	FROM tree ORDER BY depth, name_key, id`, request.NodeID)
	if err != nil {
		return Node{}, WrapError(CodeInvalid, op, request.NodeID, err)
	}
	var tree []copyNode
	maxDepth := 0
	for rows.Next() {
		var item copyNode
		if err := rows.Scan(&item.id, &item.parentID, &item.kind, &item.name, &item.nameKey, &item.mime,
			&item.size, &item.currentVersion, &item.depth); err != nil {
			rows.Close()
			return Node{}, err
		}
		if item.depth > maxDepth {
			maxDepth = item.depth
		}
		tree = append(tree, item)
	}
	if err := rows.Close(); err != nil {
		return Node{}, err
	}
	if len(tree) == 0 {
		return Node{}, NewError(CodeNotFound, op, request.NodeID, "node not found")
	}
	if err := checkItemLimit(ctx, tx, sourceAccess.OwnerID, int64(len(tree))); err != nil {
		return Node{}, err
	}
	destinationDepth, err := ancestorDepth(ctx, tx, request.DestinationID)
	if err != nil {
		return Node{}, err
	}
	if destinationDepth+1+maxDepth > 100 {
		return Node{}, NewError(CodeInvalid, op, request.NodeID, "copy would exceed the maximum tree depth of 100")
	}

	rootName := request.Name
	if rootName == "" {
		rootName = source.Name
	}
	rootName, rootKey, err := NormalizeName(rootName)
	if err != nil {
		return Node{}, err
	}
	var collision int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE owner_id = ? AND parent_id = ? AND name_key = ? AND trashed_at IS NULL`,
		sourceAccess.OwnerID, request.DestinationID, rootKey).Scan(&collision)
	if err == nil {
		if !request.KeepBoth {
			return Node{}, NewError(CodeConflict, op, request.DestinationID, "a sibling already has that name")
		}
		rootName, rootKey, err = nextAvailableName(rootName, func(key string) (bool, error) {
			var exists int
			err := tx.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE owner_id = ? AND parent_id = ? AND name_key = ? AND trashed_at IS NULL`,
				sourceAccess.OwnerID, request.DestinationID, key).Scan(&exists)
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return err == nil, err
		})
		if err != nil {
			return Node{}, err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Node{}, err
	}

	idMap := make(map[string]string, len(tree))
	rootCopyID := ""
	now := timeText(s.now())
	for index, item := range tree {
		newNodeID, err := s.newID()
		if err != nil {
			return Node{}, fmt.Errorf("%s: generate node ID: %w", op, err)
		}
		idMap[item.id] = newNodeID
		parentID := request.DestinationID
		name, key := item.name, item.nameKey
		if index == 0 {
			rootCopyID = newNodeID
			name, key = rootName, rootKey
		} else {
			mapped, ok := idMap[item.parentID]
			if !ok {
				return Node{}, NewError(CodeInvalidState, op, item.id, "copy tree parent is missing")
			}
			parentID = mapped
		}
		var versionID any
		if item.kind == string(KindFile) {
			if !item.currentVersion.Valid {
				return Node{}, NewError(CodeInvalidState, op, item.id, "file has no current version")
			}
			value, err := s.newID()
			if err != nil {
				return Node{}, err
			}
			versionID = value
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO nodes
			(id, owner_id, parent_id, kind, name, name_key, mime_type, size_bytes, current_version_id,
			 revision, created_by, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)`, newNodeID, sourceAccess.OwnerID, parentID,
			item.kind, name, key, nullableStringValue(item.mime), item.size, versionID, request.ActorID, now, now); err != nil {
			return Node{}, mapConstraint(op, item.id, err)
		}
		if item.kind == string(KindFile) {
			var blobID, checksum, mimeType string
			var size int64
			if err := tx.QueryRowContext(ctx, `SELECT blob_id, size_bytes, sha256, mime_type FROM file_versions
				WHERE id = ?`, item.currentVersion.String).Scan(&blobID, &size, &checksum, &mimeType); err != nil {
				return Node{}, WrapError(CodeInvalidState, op, item.id, err)
			}
			result, err := tx.ExecContext(ctx, "UPDATE blobs SET ref_count = ref_count + 1 WHERE id = ? AND state = 'ready'", blobID)
			if err != nil {
				return Node{}, err
			}
			if affected, _ := result.RowsAffected(); affected != 1 {
				return Node{}, NewError(CodeInvalidState, op, blobID, "source blob is not ready")
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO file_versions
				(id, node_id, blob_id, sequence, size_bytes, sha256, mime_type, created_by, created_at)
				VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)`, versionID, newNodeID, blobID, size, checksum, mimeType, request.ActorID, now); err != nil {
				return Node{}, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Node{}, err
	}
	return s.Get(ctx, request.ActorID, rootCopyID)
}

func nullableStringValue(value sql.NullString) any {
	if value.Valid {
		return value.String
	}
	return nil
}
