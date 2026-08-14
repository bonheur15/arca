// Package uploads implements Arca's durable Tus upload state machine.
package uploads

import (
	"context"
	"io"
	"time"
)

const (
	TusVersion        = "1.0.0"
	DefaultTTL        = 24 * time.Hour
	DefaultMaxChunk   = int64(64 << 20)
	MaxMetadataLength = 8 << 10
)

type State string

const (
	StatePending    State = "pending"
	StateFinalizing State = "finalizing"
	StateCompleted  State = "completed"
	StateCancelled  State = "cancelled"
	StateExpired    State = "expired"
	StateFailed     State = "failed"
)

type ConflictMode string

const (
	ConflictFail     ConflictMode = "fail"
	ConflictKeepBoth ConflictMode = "keep_both"
	ConflictReplace  ConflictMode = "replace"
)

type Upload struct {
	ID               string       `json:"id"`
	ActorID          string       `json:"actor_id"`
	OwnerID          string       `json:"owner_id"`
	ParentID         string       `json:"parent_id"`
	Name             string       `json:"name"`
	ExpectedBytes    int64        `json:"expected_bytes"`
	CommittedBytes   int64        `json:"committed_bytes"`
	ReservedBytes    int64        `json:"reserved_bytes"`
	ConflictMode     ConflictMode `json:"conflict_mode"`
	ReplaceNodeID    *string      `json:"replace_node_id,omitempty"`
	ReplaceRevision  *int64       `json:"replace_revision,omitempty"`
	ShareID          *string      `json:"share_id,omitempty"`
	State            State        `json:"state"`
	ErrorCode        *string      `json:"error_code,omitempty"`
	ExpiresAt        time.Time    `json:"expires_at"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"`
	NodeID           *string      `json:"node_id,omitempty"`
	CurrentVersionID *string      `json:"current_version_id,omitempty"`
	stagingKey       string
	intendedBlobKey  *string
}

type CreateRequest struct {
	ActorID         string
	ParentID        string
	Name            string
	ExpectedBytes   int64
	ConflictMode    ConflictMode
	ReplaceNodeID   string
	ReplaceRevision int64
	ShareID         string
}

type PatchRequest struct {
	ActorID           string
	UploadID          string
	Offset            int64
	ContentLength     int64
	Body              io.Reader
	ChecksumAlgorithm string
	Checksum          []byte
}

type Checksum struct {
	Algorithm string
	Digest    []byte
}

type Storage interface {
	OpenStaging(uploadID string) (StagingFile, error)
	OpenStagingRead(uploadID string) (io.ReadCloser, error)
	StagingSize(uploadID string) (int64, error)
	TruncateStaging(uploadID string, size int64) error
	RemoveStaging(uploadID string) error
	Finalize(uploadID, storageKey string) error
	OpenBlob(storageKey string) (io.ReadCloser, error)
	RemoveBlob(storageKey string) error
	QuarantineBlob(storageKey string) error
	ListBlobKeys() ([]string, error)
	FreeBytes() (int64, error)
}

type StagingFile interface {
	io.Writer
	Sync() error
	Close() error
}

type FinalizeHook func(context.Context, FinalizePoint, Upload) error

type FinalizePoint string

const (
	BeforeStateFinalizing FinalizePoint = "before_state_finalizing"
	AfterStateFinalizing  FinalizePoint = "after_state_finalizing"
	AfterBlobRename       FinalizePoint = "after_blob_rename"
	BeforeMetadataCommit  FinalizePoint = "before_metadata_commit"
)
