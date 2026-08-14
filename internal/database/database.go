// Package database owns Arca's SQLite lifecycle and transaction primitives.
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

const (
	defaultReadConnections = 4
	busyTimeoutMS          = 5000
)

// Config controls how an Arca SQLite database is opened.
type Config struct {
	Path         string
	Migrations   fs.FS
	MaxReadConns int
}

// DB separates the single serialized writer from a bounded read pool.
type DB struct {
	writer  *sql.DB
	reader  *sql.DB
	path    string
	version string
	closed  atomic.Bool
}

// Open creates the database parent directory, validates SQLite, applies all
// migrations, and returns a ready writer/read-pool pair.
func Open(ctx context.Context, cfg Config) (*DB, error) {
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, errors.New("database path is required")
	}
	abs, err := filepath.Abs(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("secure database directory: %w", err)
	}
	if err := validateLocalFilesystem(filepath.Dir(abs)); err != nil {
		return nil, err
	}
	if err := validateSQLitePaths(abs); err != nil {
		return nil, err
	}

	writer, err := sql.Open("sqlite", sqliteDSN(abs, false))
	if err != nil {
		return nil, fmt.Errorf("open SQLite writer: %w", err)
	}
	writer.SetMaxOpenConns(1)
	writer.SetMaxIdleConns(1)
	cleanupWriter := true
	defer func() {
		if cleanupWriter {
			_ = writer.Close()
		}
	}()

	if err := writer.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping SQLite writer: %w", err)
	}
	var version string
	if err := writer.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&version); err != nil {
		return nil, fmt.Errorf("read SQLite version: %w", err)
	}
	if err := ValidateSQLiteVersion(version); err != nil {
		return nil, err
	}
	if err := verifyPragmas(ctx, writer, false); err != nil {
		return nil, err
	}
	if cfg.Migrations != nil {
		if err := Migrate(ctx, writer, cfg.Migrations); err != nil {
			return nil, err
		}
	}
	if err := secureSQLitePaths(abs); err != nil {
		return nil, err
	}

	reads := cfg.MaxReadConns
	if reads <= 0 {
		reads = defaultReadConnections
	}
	reader, err := sql.Open("sqlite", sqliteDSN(abs, true))
	if err != nil {
		return nil, fmt.Errorf("open SQLite reader: %w", err)
	}
	reader.SetMaxOpenConns(reads)
	reader.SetMaxIdleConns(reads)
	cleanupReader := true
	defer func() {
		if cleanupReader {
			_ = reader.Close()
		}
	}()
	if err := reader.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping SQLite reader: %w", err)
	}
	if err := verifyPragmas(ctx, reader, true); err != nil {
		return nil, err
	}

	cleanupWriter = false
	cleanupReader = false
	return &DB{writer: writer, reader: reader, path: abs, version: version}, nil
}

func validateSQLitePaths(databasePath string) error {
	for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm", databasePath + "-journal"} {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect SQLite path %q: %w", path, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("SQLite path %q must be a regular file", path)
		}
	}
	return nil
}

func secureSQLitePaths(databasePath string) error {
	for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
		if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("secure SQLite file %q: %w", path, err)
		}
	}
	return nil
}

func sqliteDSN(path string, readOnly bool) string {
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	q := u.Query()
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeoutMS))
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "journal_mode(WAL)")
	if readOnly {
		q.Add("_pragma", "query_only(ON)")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func verifyPragmas(ctx context.Context, db *sql.DB, readOnly bool) error {
	var foreignKeys int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		return fmt.Errorf("SQLite foreign_keys pragma unavailable: value=%d error=%w", foreignKeys, err)
	}
	var journal string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		return fmt.Errorf("read SQLite journal mode: %w", err)
	}
	if !strings.EqualFold(journal, "wal") {
		return fmt.Errorf("SQLite refused WAL mode: got %q", journal)
	}
	var synchronous int
	if err := db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		return fmt.Errorf("read SQLite synchronous mode: %w", err)
	}
	if synchronous != 2 { // SQLITE_SYNC_FULL
		return fmt.Errorf("SQLite refused synchronous=FULL: got %d", synchronous)
	}
	if readOnly {
		var queryOnly int
		if err := db.QueryRowContext(ctx, "PRAGMA query_only").Scan(&queryOnly); err != nil || queryOnly != 1 {
			return fmt.Errorf("SQLite reader is not query-only: value=%d error=%w", queryOnly, err)
		}
	}
	return nil
}

// ValidateSQLiteVersion rejects releases affected by SQLite's WAL-reset race.
// The upstream fixes are 3.51.3+, plus the maintained 3.50.7 and 3.44.6
// backport branches.
func ValidateSQLiteVersion(version string) error {
	parts := strings.Split(version, ".")
	if len(parts) < 3 {
		return fmt.Errorf("unsupported SQLite version %q", version)
	}
	n := make([]int, 3)
	for i := range n {
		v, err := strconv.Atoi(parts[i])
		if err != nil {
			return fmt.Errorf("unsupported SQLite version %q", version)
		}
		n[i] = v
	}
	if n[0] != 3 {
		return fmt.Errorf("unsupported SQLite major version %q", version)
	}
	safe := n[1] > 51 || (n[1] == 51 && n[2] >= 3) ||
		(n[1] == 50 && n[2] >= 7) || (n[1] == 44 && n[2] >= 6)
	if !safe {
		return fmt.Errorf("SQLite %s is affected by the WAL-reset corruption bug; require 3.51.3+, 3.50.7+, or 3.44.6+ on its maintained branch", version)
	}
	return nil
}

// Writer returns the only writable database/sql pool. It has exactly one
// connection so Arca writes are serialized.
func (d *DB) Writer() *sql.DB { return d.writer }

// Reader returns the bounded, query-only pool.
func (d *DB) Reader() *sql.DB { return d.reader }

func (d *DB) Path() string          { return d.path }
func (d *DB) SQLiteVersion() string { return d.version }

// Close checkpoints the WAL and closes both pools. It is idempotent.
func (d *DB) Close() error {
	if d == nil || !d.closed.CompareAndSwap(false, true) {
		return nil
	}
	var errs []error
	if d.reader != nil {
		if err := d.reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close SQLite reader: %w", err))
		}
	}
	if d.writer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, checkpointErr := d.writer.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
		cancel()
		if checkpointErr != nil {
			errs = append(errs, fmt.Errorf("checkpoint SQLite WAL: %w", checkpointErr))
		}
		if err := d.writer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close SQLite writer: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Check verifies that the database is reachable and internally consistent.
func (d *DB) Check(ctx context.Context) error {
	if d == nil || d.closed.Load() {
		return errors.New("database is closed")
	}
	var result string
	if err := d.reader.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return fmt.Errorf("SQLite quick_check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("SQLite quick_check failed: %s", result)
	}
	return nil
}
