package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Handler func(context.Context, json.RawMessage) error

type Job struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Payload     json.RawMessage `json:"payload"`
	State       string          `json:"state"`
	Attempts    int             `json:"attempts"`
	MaxAttempts int             `json:"max_attempts"`
	RunAfter    time.Time       `json:"run_after"`
	LastError   string          `json:"last_error,omitempty"`
}

type Runner struct {
	db       *sql.DB
	logger   *slog.Logger
	handlers map[string]Handler
	poll     time.Duration
	lease    time.Duration
	now      func() time.Time
	wake     chan struct{}
	mu       sync.RWMutex
}

func New(db *sql.DB, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{
		db: db, logger: logger, handlers: make(map[string]Handler),
		poll: time.Second, lease: 2 * time.Minute, now: time.Now, wake: make(chan struct{}, 1),
	}
}

func (r *Runner) Register(kind string, handler Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if kind == "" || handler == nil {
		panic("jobs: kind and handler are required")
	}
	if _, exists := r.handlers[kind]; exists {
		panic("jobs: duplicate handler for " + kind)
	}
	r.handlers[kind] = handler
}

func (r *Runner) Enqueue(ctx context.Context, kind string, payload any, runAfter time.Time) (string, error) {
	r.mu.RLock()
	_, registered := r.handlers[kind]
	r.mu.RUnlock()
	if !registered {
		return "", fmt.Errorf("jobs: no handler registered for %q", kind)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode job payload: %w", err)
	}
	if runAfter.IsZero() {
		runAfter = r.now()
	}
	id := newID()
	now := stamp(r.now())
	_, err = r.db.ExecContext(ctx, `INSERT INTO jobs
        (id, kind, payload, state, attempts, max_attempts, run_after, created_at, updated_at)
        VALUES (?, ?, ?, 'queued', 0, 8, ?, ?, ?)`, id, kind, string(body), stamp(runAfter), now, now)
	if err != nil {
		return "", err
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return id, nil
}

func (r *Runner) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.poll)
	defer ticker.Stop()
	for {
		if err := r.RunOnce(ctx); err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, context.Canceled) {
			r.logger.Error("background job loop failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-r.wake:
		}
	}
}

func (r *Runner) RunOnce(ctx context.Context) error {
	job, err := r.claim(ctx)
	if err != nil {
		return err
	}
	r.mu.RLock()
	handler := r.handlers[job.Kind]
	r.mu.RUnlock()
	if handler == nil {
		return r.fail(ctx, job, errors.New("handler is not registered"))
	}
	jobCtx, cancel := context.WithTimeout(ctx, r.lease)
	err = handler(jobCtx, job.Payload)
	cancel()
	if err != nil {
		return r.fail(ctx, job, err)
	}
	_, err = r.db.ExecContext(ctx, `UPDATE jobs SET state = 'completed', lease_until = NULL, last_error = NULL, updated_at = ? WHERE id = ?`, stamp(r.now()), job.ID)
	return err
}

func (r *Runner) claim(ctx context.Context) (Job, error) {
	now := r.now().UTC()
	leaseUntil := now.Add(r.lease)
	row := r.db.QueryRowContext(ctx, `
        UPDATE jobs SET state = 'running', attempts = attempts + 1, lease_until = ?, updated_at = ?
        WHERE id = (
            SELECT id FROM jobs
            WHERE (state = 'queued' OR (state = 'running' AND lease_until < ?)) AND run_after <= ?
            ORDER BY run_after, created_at LIMIT 1
        )
        RETURNING id, kind, payload, state, attempts, max_attempts, run_after, COALESCE(last_error, '')`,
		stamp(leaseUntil), stamp(now), stamp(now), stamp(now))
	var job Job
	var payload, runAfter string
	if err := row.Scan(&job.ID, &job.Kind, &payload, &job.State, &job.Attempts, &job.MaxAttempts, &runAfter, &job.LastError); err != nil {
		return Job{}, err
	}
	job.Payload = json.RawMessage(payload)
	parsed, err := time.Parse(time.RFC3339Nano, runAfter)
	if err != nil {
		return Job{}, err
	}
	job.RunAfter = parsed
	return job, nil
}

func (r *Runner) fail(ctx context.Context, job Job, cause error) error {
	state := "queued"
	if job.Attempts >= job.MaxAttempts {
		state = "dead"
	}
	delay := time.Duration(math.Min(math.Pow(2, float64(job.Attempts)), 3600)) * time.Second
	now := r.now().UTC()
	_, updateErr := r.db.ExecContext(ctx, `UPDATE jobs SET state = ?, run_after = ?, lease_until = NULL, last_error = ?, updated_at = ? WHERE id = ?`,
		state, stamp(now.Add(delay)), truncate(cause.Error(), 2000), stamp(now), job.ID)
	if updateErr != nil {
		return errors.Join(cause, updateErr)
	}
	r.logger.Warn("background job failed", "job_id", job.ID, "kind", job.Kind, "attempt", job.Attempts, "state", state, "error", cause)
	return cause
}

func (r *Runner) Retry(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, `UPDATE jobs SET state = 'queued', run_after = ?, lease_until = NULL, last_error = NULL, updated_at = ? WHERE id = ? AND state IN ('failed', 'dead')`, stamp(r.now()), stamp(r.now()), id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return sql.ErrNoRows
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

func (r *Runner) List(ctx context.Context, limit int) ([]Job, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, kind, payload, state, attempts, max_attempts, run_after, COALESCE(last_error, '') FROM jobs ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Job
	for rows.Next() {
		var job Job
		var payload, runAfter string
		if err := rows.Scan(&job.ID, &job.Kind, &payload, &job.State, &job.Attempts, &job.MaxAttempts, &runAfter, &job.LastError); err != nil {
			return nil, err
		}
		job.Payload = json.RawMessage(payload)
		job.RunAfter, _ = time.Parse(time.RFC3339Nano, runAfter)
		result = append(result, job)
	}
	return result, rows.Err()
}

func truncate(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}

func stamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func newID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}
