// Package audit records security and administrative activity.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Event is an append-only audit record. Metadata must never contain secrets,
// authentication codes, session cookies, bearer tokens, or file contents.
type Event struct {
	ID         string
	ActorID    *string
	Action     string
	TargetType string
	TargetID   string
	IPAddress  string
	UserAgent  string
	RequestID  string
	Metadata   map[string]any
	CreatedAt  time.Time
}

// Recorder is the boundary used by domain services. Implementations should
// preserve event order and return persistence failures to the caller.
type Recorder interface {
	Record(context.Context, Event) error
}

// NopRecorder is useful for commands and tests that deliberately do not need
// durable auditing.
type NopRecorder struct{}

func (NopRecorder) Record(context.Context, Event) error { return nil }

// SQLRecorder appends events to the audit_events table.
type SQLRecorder struct {
	db  *sql.DB
	now func() time.Time
}

func NewSQLRecorder(db *sql.DB) *SQLRecorder {
	return &SQLRecorder{db: db, now: time.Now}
}

func (r *SQLRecorder) Record(ctx context.Context, event Event) error {
	if r == nil || r.db == nil {
		return errors.New("audit: database is required")
	}
	if event.Action == "" {
		return errors.New("audit: action is required")
	}
	if event.ID == "" {
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("audit: generate id: %w", err)
		}
		event.ID = id.String()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = r.now().UTC()
	}
	metadata := event.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("audit: encode metadata: %w", err)
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO audit_events (
			id, actor_id, action, target_type, target_id, ip_address,
			user_agent, request_id, metadata, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, nullableString(event.ActorID), event.Action,
		nullIfEmpty(event.TargetType), nullIfEmpty(event.TargetID),
		nullIfEmpty(event.IPAddress), nullIfEmpty(event.UserAgent),
		nullIfEmpty(event.RequestID), string(encoded), event.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("audit: insert event: %w", err)
	}
	return nil
}

func nullableString(value *string) any {
	if value == nil || *value == "" {
		return nil
	}
	return *value
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}
