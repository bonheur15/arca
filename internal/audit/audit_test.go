package audit_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"arca/internal/audit"
	"arca/internal/database"
	"arca/migrations"
)

func TestSQLRecorderAppendsStructuredEvent(t *testing.T) {
	db, err := database.Open(context.Background(), database.Config{
		Path: filepath.Join(t.TempDir(), "arca.sqlite3"), Migrations: migrations.Files,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	recorder := audit.NewSQLRecorder(db.Writer())
	targetID := "019c0000-0000-7000-8000-000000000001"
	if err := recorder.Record(context.Background(), audit.Event{
		Action: "user.preferences_changed", TargetType: "user",
		TargetID: targetID, IPAddress: "192.0.2.1", UserAgent: "test",
		RequestID: "request_1", Metadata: map[string]any{"theme": "dark"},
	}); err != nil {
		t.Fatal(err)
	}
	var id, action, metadata string
	if err := db.Reader().QueryRow(`SELECT id, action, metadata FROM audit_events`).Scan(&id, &action, &metadata); err != nil {
		t.Fatal(err)
	}
	if id == "" || action != "user.preferences_changed" {
		t.Fatalf("id = %q action = %q", id, action)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(metadata), &decoded); err != nil || decoded["theme"] != "dark" {
		t.Fatalf("metadata = %q, decoded = %#v, err = %v", metadata, decoded, err)
	}
}

func TestSQLRecorderRejectsMissingDatabaseAndAction(t *testing.T) {
	if err := (*audit.SQLRecorder)(nil).Record(context.Background(), audit.Event{Action: "x"}); err == nil {
		t.Fatal("nil recorder accepted event")
	}
	db, err := database.Open(context.Background(), database.Config{
		Path: filepath.Join(t.TempDir(), "arca.sqlite3"), Migrations: migrations.Files,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := audit.NewSQLRecorder(db.Writer()).Record(context.Background(), audit.Event{}); err == nil {
		t.Fatal("recorder accepted an empty action")
	}
}
