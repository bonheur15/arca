package files

import (
	"database/sql"
	"time"
)

type Kind string

const (
	KindFolder Kind = "folder"
	KindFile   Kind = "file"
)

type Node struct {
	ID               string       `json:"id"`
	OwnerID          string       `json:"owner_id"`
	ParentID         *string      `json:"parent_id,omitempty"`
	Kind             Kind         `json:"kind"`
	Name             string       `json:"name"`
	MIMEType         *string      `json:"mime_type,omitempty"`
	SizeBytes        int64        `json:"size_bytes"`
	CurrentVersionID *string      `json:"current_version_id,omitempty"`
	Revision         int64        `json:"revision"`
	CreatedBy        string       `json:"created_by"`
	TrashedAt        *time.Time   `json:"trashed_at,omitempty"`
	OriginalParentID *string      `json:"original_parent_id,omitempty"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
	Favorite         bool         `json:"favorite"`
	Capabilities     Capabilities `json:"capabilities"`
}

type Capabilities struct {
	Read        bool `json:"read"`
	CreateChild bool `json:"create_child"`
	Rename      bool `json:"rename"`
	Move        bool `json:"move"`
	Trash       bool `json:"trash"`
	Purge       bool `json:"purge"`
	Share       bool `json:"share"`
}

type FileVersion struct {
	ID        string    `json:"id"`
	NodeID    string    `json:"node_id"`
	BlobID    string    `json:"blob_id"`
	Sequence  int64     `json:"sequence"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	MIMEType  string    `json:"mime_type"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

type Content struct {
	Node       Node
	Version    FileVersion
	StorageKey string
	BlobState  string
}

type ListOptions struct {
	Limit  int
	Cursor string
}

type NodePage struct {
	Items      []Node `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type SearchOptions struct {
	Query    string
	Kind     Kind
	MIMEType string
	Limit    int
	Cursor   string
}

type AccessAction string

const (
	ActionRead        AccessAction = "read"
	ActionCreateChild AccessAction = "create_child"
	ActionRename      AccessAction = "rename"
	ActionMove        AccessAction = "move"
	ActionReplace     AccessAction = "replace"
	ActionTrash       AccessAction = "trash"
	ActionPurge       AccessAction = "purge"
	ActionRestore     AccessAction = "restore"
	ActionShare       AccessAction = "share"
)

type Access struct {
	ActorID            string
	OwnerID            string
	NodeID             string
	Owner              bool
	Support            bool
	ShareID            string
	ShareRootID        string
	Permission         string
	AllowEditorUploads bool
	EditorAllowance    sql.NullInt64
}

type PurgeResult struct {
	NodesDeleted    int64
	VersionsDeleted int64
	BlobsQueued     int64
}
