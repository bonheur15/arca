package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"arca/internal/accounts"
	"arca/internal/audit"

	workos "github.com/workos/workos-go/v10"
)

const (
	EventUserUpdated    = "user.updated"
	EventUserDeleted    = "user.deleted"
	EventSessionRevoked = "session.revoked"
)

type IdentityEvent struct {
	ID           string
	Kind         string
	WorkOSUserID string
	Email        string
	SessionID    string
	ExpiresAt    time.Time
}

type EventSource interface {
	ListIdentityEvents(context.Context, string, int) ([]IdentityEvent, string, error)
}

// ListIdentityEvents retrieves one bounded page in chronological order. The
// returned cursor is safe to persist only after every returned event succeeds.
func (p *WorkOSProvider) ListIdentityEvents(ctx context.Context, after string, limit int) ([]IdentityEvent, string, error) {
	if limit < 1 || limit > 100 {
		limit = 100
	}
	order := string(workos.PaginationOrderAsc)
	iterator := p.client.Events().List(ctx, &workos.EventsListParams{
		PaginationParams: workos.PaginationParams{
			After: optionalString(after), Limit: &limit, Order: &order,
		},
		Events: []string{EventUserUpdated, EventUserDeleted, EventSessionRevoked},
	})
	events := make([]IdentityEvent, 0, limit)
	for len(events) < limit && iterator.Next() {
		event := iterator.Current()
		if event == nil {
			continue
		}
		converted, err := convertWorkOSEvent(*event)
		if err != nil {
			return nil, after, err
		}
		events = append(events, converted)
	}
	if err := iterator.Err(); err != nil {
		return nil, after, fmt.Errorf("auth: list WorkOS events: %w", err)
	}
	next := after
	if len(events) > 0 {
		next = events[len(events)-1].ID
	}
	return events, next, nil
}

func convertWorkOSEvent(event workos.EventSchema) (IdentityEvent, error) {
	converted := IdentityEvent{ID: event.ID, Kind: event.Event}
	if converted.ID == "" {
		return IdentityEvent{}, errors.New("auth: WorkOS event is missing an id")
	}
	switch converted.Kind {
	case EventUserUpdated, EventUserDeleted:
		converted.WorkOSUserID = stringField(event.Data, "id")
		converted.Email = stringField(event.Data, "email")
		if converted.WorkOSUserID == "" {
			return IdentityEvent{}, fmt.Errorf("auth: WorkOS %s event is missing user id", converted.Kind)
		}
	case EventSessionRevoked:
		converted.SessionID = stringField(event.Data, "id")
		converted.WorkOSUserID = stringField(event.Data, "user_id")
		expiresAt := stringField(event.Data, "expires_at")
		if converted.SessionID == "" {
			return IdentityEvent{}, errors.New("auth: WorkOS session.revoked event is missing session id")
		}
		if expiresAt != "" {
			parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
			if err != nil {
				return IdentityEvent{}, fmt.Errorf("auth: parse revoked session expiration: %w", err)
			}
			converted.ExpiresAt = parsed.UTC()
		}
	default:
		return IdentityEvent{}, fmt.Errorf("auth: unsupported WorkOS event %q", converted.Kind)
	}
	return converted, nil
}

func stringField(data map[string]any, key string) string {
	value, _ := data[key].(string)
	return value
}

type EventReconciler struct {
	db       *sql.DB
	accounts *accounts.Repository
	auth     *AuthService
	source   EventSource
	audit    audit.Recorder
	now      func() time.Time
}

func NewEventReconciler(db *sql.DB, repository *accounts.Repository, authService *AuthService, source EventSource, recorder audit.Recorder) (*EventReconciler, error) {
	if db == nil || repository == nil || authService == nil || source == nil {
		return nil, errors.New("auth: event reconciler dependencies are required")
	}
	if recorder == nil {
		recorder = audit.NopRecorder{}
	}
	return &EventReconciler{db: db, accounts: repository, auth: authService, source: source, audit: recorder, now: time.Now}, nil
}

// PollOnce processes at most limit identity events. Replays are safe because
// each mutation is idempotent and the cursor advances only after the full page.
func (r *EventReconciler) PollOnce(ctx context.Context, limit int) (int, error) {
	cursor, err := r.cursor(ctx)
	if err != nil {
		return 0, err
	}
	events, next, err := r.source.ListIdentityEvents(ctx, cursor, limit)
	if err != nil {
		_ = r.recordPollFailure(ctx, err)
		return 0, err
	}
	if len(events) > 0 && next == cursor {
		err := errors.New("auth: WorkOS event source did not advance its cursor")
		_ = r.recordPollFailure(ctx, err)
		return 0, err
	}
	for _, event := range events {
		if err := r.apply(ctx, event); err != nil {
			_ = r.recordPollFailure(ctx, err)
			return 0, fmt.Errorf("auth: reconcile WorkOS event %s: %w", event.ID, err)
		}
	}
	if err := r.updateCursor(ctx, next, ""); err != nil {
		return 0, err
	}
	return len(events), nil
}

// Run polls immediately and then at interval until cancellation. Poll errors
// are reported but remain failure-isolated so a temporary WorkOS outage does
// not stop Arca's file-serving path.
func (r *EventReconciler) Run(ctx context.Context, interval time.Duration, report func(error)) error {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	poll := func() {
		for range 10 { // Bound catch-up work per tick.
			count, err := r.PollOnce(ctx, 100)
			if err != nil {
				if report != nil {
					report(err)
				}
				return
			}
			if count < 100 {
				return
			}
		}
	}
	poll()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			poll()
		}
	}
}

func (r *EventReconciler) apply(ctx context.Context, event IdentityEvent) error {
	switch event.Kind {
	case EventUserUpdated:
		if event.Email == "" {
			return errors.New("user.updated event has no email")
		}
		user, err := r.accounts.UpdateIdentityEmail(ctx, event.WorkOSUserID, event.Email)
		if errors.Is(err, accounts.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return r.audit.Record(ctx, audit.Event{ActorID: nil, Action: "identity.user_updated", TargetType: "user", TargetID: user.ID})
	case EventUserDeleted:
		user, err := r.accounts.SuspendIdentityDeleted(ctx, event.WorkOSUserID)
		if errors.Is(err, accounts.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return r.audit.Record(ctx, audit.Event{ActorID: nil, Action: "identity.user_deleted", TargetType: "user", TargetID: user.ID})
	case EventSessionRevoked:
		expiresAt := event.ExpiresAt
		if expiresAt.IsZero() || !expiresAt.After(r.now()) {
			expiresAt = r.now().UTC().Add(30 * 24 * time.Hour)
		}
		userID := ""
		if event.WorkOSUserID != "" {
			if user, err := r.accounts.GetUserByWorkOSID(ctx, event.WorkOSUserID); err == nil {
				userID = user.ID
			}
		}
		if err := r.auth.revokeLocally(ctx, event.SessionID, userID, expiresAt); err != nil {
			return err
		}
		return r.audit.Record(ctx, audit.Event{ActorID: nil, Action: "identity.session_revoked", TargetType: "session", TargetID: event.SessionID})
	default:
		return fmt.Errorf("unsupported identity event %q", event.Kind)
	}
}

func (r *EventReconciler) cursor(ctx context.Context) (string, error) {
	var cursor sql.NullString
	if err := r.db.QueryRowContext(ctx, `SELECT cursor FROM workos_event_cursor WHERE singleton = 1`).Scan(&cursor); err != nil {
		return "", fmt.Errorf("auth: read WorkOS event cursor: %w", err)
	}
	return cursor.String, nil
}

func (r *EventReconciler) updateCursor(ctx context.Context, cursor, lastError string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE workos_event_cursor SET cursor = ?, last_polled_at = ?, last_error = ? WHERE singleton = 1`,
		nullIfEmpty(cursor), formatTime(r.now().UTC()), nullIfEmpty(lastError))
	if err != nil {
		return fmt.Errorf("auth: update WorkOS event cursor: %w", err)
	}
	return nil
}

func (r *EventReconciler) recordPollFailure(ctx context.Context, pollErr error) error {
	return r.updateCursor(ctx, mustCursor(r.cursor(ctx)), truncate(pollErr.Error(), 1000))
}

func mustCursor(cursor string, err error) string {
	if err != nil {
		return ""
	}
	return cursor
}
