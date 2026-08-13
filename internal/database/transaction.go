package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
)

// Queryer is implemented by sql.DB, sql.Tx, and ImmediateTx.
type Queryer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// ImmediateTx is a transaction started with BEGIN IMMEDIATE. It reserves the
// SQLite writer before reading quota or conflict state, avoiding read/write
// promotion races.
type ImmediateTx struct {
	conn *sql.Conn
	done atomic.Bool
}

func (d *DB) BeginImmediate(ctx context.Context) (*ImmediateTx, error) {
	if d == nil || d.closed.Load() {
		return nil, errors.New("database is closed")
	}
	conn, err := d.writer.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire SQLite writer: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("begin immediate SQLite transaction: %w", err)
	}
	return &ImmediateTx{conn: conn}, nil
}

func (t *ImmediateTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.conn.ExecContext(ctx, query, args...)
}

func (t *ImmediateTx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.conn.QueryContext(ctx, query, args...)
}

func (t *ImmediateTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.conn.QueryRowContext(ctx, query, args...)
}

func (t *ImmediateTx) Commit(ctx context.Context) error {
	if t == nil || !t.done.CompareAndSwap(false, true) {
		return sql.ErrTxDone
	}
	_, err := t.conn.ExecContext(ctx, "COMMIT")
	closeErr := t.conn.Close()
	if err != nil {
		return fmt.Errorf("commit SQLite transaction: %w", err)
	}
	return closeErr
}

func (t *ImmediateTx) Rollback(ctx context.Context) error {
	if t == nil || !t.done.CompareAndSwap(false, true) {
		return sql.ErrTxDone
	}
	_, err := t.conn.ExecContext(ctx, "ROLLBACK")
	closeErr := t.conn.Close()
	if err != nil {
		return fmt.Errorf("rollback SQLite transaction: %w", err)
	}
	return closeErr
}
