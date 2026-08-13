package database_test

import (
	"context"
	"testing"
	"testing/fstest"

	"arca/internal/database"
)

func TestOpenMigrateAndImmediateTransaction(t *testing.T) {
	t.Parallel()
	migrations := fstest.MapFS{
		"001_test.sql": {Data: []byte("CREATE TABLE widgets (id TEXT PRIMARY KEY, value TEXT NOT NULL);")},
	}
	db, err := database.Open(context.Background(), database.Config{
		Path:       t.TempDir() + "/db/arca.sqlite3",
		Migrations: migrations,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	tx, err := db.BeginImmediate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO widgets(id, value) VALUES ('1', 'arca')"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := db.Reader().QueryRow("SELECT value FROM widgets WHERE id = '1'").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "arca" {
		t.Fatalf("value = %q", got)
	}
	if err := db.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestReaderIsQueryOnly(t *testing.T) {
	t.Parallel()
	db, err := database.Open(context.Background(), database.Config{
		Path: t.TempDir() + "/arca.sqlite3",
		Migrations: fstest.MapFS{
			"001_test.sql": {Data: []byte("CREATE TABLE widgets (id INTEGER);")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Reader().Exec("INSERT INTO widgets(id) VALUES (1)"); err == nil {
		t.Fatal("query-only reader accepted a write")
	}
}

func TestValidateSQLiteVersion(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"3.51.3", "3.53.3", "3.50.7", "3.44.6"} {
		if err := database.ValidateSQLiteVersion(version); err != nil {
			t.Errorf("%s should be safe: %v", version, err)
		}
	}
	for _, version := range []string{"3.51.2", "3.50.6", "3.49.1", "3.44.5", "nope"} {
		if err := database.ValidateSQLiteVersion(version); err == nil {
			t.Errorf("%s should be rejected", version)
		}
	}
}
