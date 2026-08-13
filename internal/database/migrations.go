package database

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type migration struct {
	version int
	name    string
	content string
}

// Migrate applies immutable, numerically prefixed .sql files transactionally.
func Migrate(ctx context.Context, db *sql.DB, migrationFS fs.FS) error {
	entries, err := fs.ReadDir(migrationFS, ".")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	var migrations []migration
	seen := make(map[int]string)
	for _, entry := range entries {
		if entry.IsDir() || path.Ext(entry.Name()) != ".sql" {
			continue
		}
		prefix := strings.SplitN(entry.Name(), "_", 2)[0]
		version, err := strconv.Atoi(prefix)
		if err != nil || version <= 0 {
			return fmt.Errorf("migration %q must start with a positive numeric prefix", entry.Name())
		}
		if prior, ok := seen[version]; ok {
			return fmt.Errorf("migrations %q and %q have duplicate version %d", prior, entry.Name(), version)
		}
		body, err := fs.ReadFile(migrationFS, entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %q: %w", entry.Name(), err)
		}
		seen[version] = entry.Name()
		migrations = append(migrations, migration{version: version, name: entry.Name(), content: string(body)})
	}
	if len(migrations) == 0 {
		return fmt.Errorf("no database migrations found")
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })

	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )`); err != nil {
		return fmt.Errorf("initialize migration ledger: %w", err)
	}
	var highest int
	if err := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&highest); err != nil {
		return fmt.Errorf("read migration version: %w", err)
	}
	latest := migrations[len(migrations)-1].version
	if highest > latest {
		return fmt.Errorf("database schema version %d is newer than binary version %d", highest, latest)
	}
	for _, m := range migrations {
		var applied int
		err := db.QueryRowContext(ctx, "SELECT 1 FROM schema_migrations WHERE version = ?", m.version).Scan(&applied)
		if err == nil {
			continue
		}
		if err != sql.ErrNoRows {
			return fmt.Errorf("inspect migration %d: %w", m.version, err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", m.version, err)
		}
		if _, err = tx.ExecContext(ctx, m.content); err == nil {
			_, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)", m.version, time.Now().UTC().Format(time.RFC3339Nano))
		}
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %d (%s): %w", m.version, m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d (%s): %w", m.version, m.name, err)
		}
	}
	return nil
}
