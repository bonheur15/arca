package files

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"arca/internal/database"
)

// Authorize checks the current tree and sharing state for every operation. A
// previously granted capability is never treated as a durable authorization.
func Authorize(ctx context.Context, q database.Queryer, actorID, nodeID string, action AccessAction, now time.Time) (Access, error) {
	const op = "authorize node"
	var access Access
	access.ActorID = actorID
	access.NodeID = nodeID
	var actorState, nodeOwner string
	err := q.QueryRowContext(ctx, `
        SELECT actor.state, n.owner_id
        FROM users actor
        JOIN nodes n ON n.id = ?
        WHERE actor.id = ?`, nodeID, actorID).Scan(&actorState, &nodeOwner)
	if errors.Is(err, sql.ErrNoRows) {
		return Access{}, NewError(CodeNotFound, op, nodeID, "node or actor not found")
	}
	if err != nil {
		return Access{}, WrapError(CodeInvalid, op, nodeID, err)
	}
	if actorState != "active" && actorState != "over_quota" {
		return Access{}, NewError(CodeForbidden, op, nodeID, "account is not active")
	}
	access.OwnerID = nodeOwner
	var trashedAncestors int
	if err := q.QueryRowContext(ctx, `WITH RECURSIVE ancestors(id, parent_id, trashed_at, depth) AS (
        SELECT id, parent_id, trashed_at, 0 FROM nodes WHERE id = ?
        UNION ALL SELECT n.id, n.parent_id, n.trashed_at, a.depth + 1
        FROM nodes n JOIN ancestors a ON n.id = a.parent_id WHERE a.depth < 100
    ) SELECT COUNT(*) FROM ancestors WHERE trashed_at IS NOT NULL`, nodeID).Scan(&trashedAncestors); err != nil {
		return Access{}, WrapError(CodeInvalid, op, nodeID, err)
	}
	if trashedAncestors != 0 {
		return Access{}, NewError(CodeNotFound, op, nodeID, "node is in trash")
	}
	if actorID == nodeOwner {
		access.Owner = true
		return access, nil
	}
	if action == ActionRead {
		var supportID string
		err := q.QueryRowContext(ctx, `
            SELECT id FROM support_access
            WHERE actor_id = ? AND target_user_id = ? AND revoked_at IS NULL AND expires_at > ?
            ORDER BY expires_at DESC LIMIT 1`, actorID, nodeOwner, timeText(now)).Scan(&supportID)
		if err == nil {
			access.Support = true
			return access, nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return Access{}, WrapError(CodeInvalid, op, nodeID, err)
		}
	}

	var allowUploads int
	err = q.QueryRowContext(ctx, `
        WITH RECURSIVE ancestors(id, parent_id, trashed_at, depth) AS (
            SELECT id, parent_id, trashed_at, 0 FROM nodes WHERE id = ?
            UNION ALL
            SELECT n.id, n.parent_id, n.trashed_at, a.depth + 1
            FROM nodes n JOIN ancestors a ON n.id = a.parent_id
            WHERE a.depth < 100
        )
        SELECT s.id, sr.node_id, s.permission, s.allow_editor_uploads, s.editor_allowance_bytes
        FROM ancestors a
        JOIN share_roots sr ON sr.node_id = a.id
        JOIN shares s ON s.id = sr.share_id
        JOIN share_recipients recipient ON recipient.share_id = s.id AND recipient.user_id = ?
        WHERE s.revoked_at IS NULL
          AND (s.expires_at IS NULL OR s.expires_at > ?)
          AND NOT EXISTS (SELECT 1 FROM ancestors WHERE trashed_at IS NOT NULL)
		ORDER BY CASE s.permission WHEN 'editor' THEN 0 ELSE 1 END, a.depth ASC
        LIMIT 1`, nodeID, actorID, timeText(now)).Scan(
		&access.ShareID, &access.ShareRootID, &access.Permission, &allowUploads, &access.EditorAllowance,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Access{}, NewError(CodeForbidden, op, nodeID, "node is not accessible")
	}
	if err != nil {
		return Access{}, WrapError(CodeInvalid, op, nodeID, err)
	}
	access.AllowEditorUploads = allowUploads == 1
	if action == ActionRead {
		return access, nil
	}
	if access.Permission != "editor" {
		return Access{}, NewError(CodeForbidden, op, nodeID, "share is read-only")
	}
	switch action {
	case ActionCreateChild, ActionRename, ActionMove, ActionReplace, ActionTrash:
		if action != ActionCreateChild && access.ShareRootID == nodeID {
			return Access{}, NewError(CodeForbidden, op, nodeID, "editors cannot mutate a shared root")
		}
		return access, nil
	default:
		return Access{}, NewError(CodeForbidden, op, nodeID, "operation is owner-only")
	}
}

func CapabilitiesFor(access Access, isRoot bool) Capabilities {
	if access.Owner {
		return Capabilities{Read: true, CreateChild: true, Rename: !isRoot, Move: !isRoot, Trash: !isRoot, Purge: !isRoot, Share: !isRoot}
	}
	if access.Support {
		return Capabilities{Read: true}
	}
	editor := access.Permission == "editor"
	isShareRoot := access.ShareRootID == access.NodeID
	return Capabilities{
		Read: true, CreateChild: editor, Rename: editor && !isShareRoot,
		Move: editor && !isShareRoot, Trash: editor && !isShareRoot,
	}
}
