package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"arca/internal/accounts"

	workos "github.com/workos/workos-go/v10"
)

type RemoteSession struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	IPAddress string     `json:"ip_address,omitempty"`
	UserAgent string     `json:"user_agent,omitempty"`
	Status    string     `json:"status"`
	ExpiresAt time.Time  `json:"expires_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type SessionDirectory interface {
	ListSessions(context.Context, string, int) ([]RemoteSession, error)
}

func (p *WorkOSProvider) ListSessions(ctx context.Context, workosUserID string, limit int) ([]RemoteSession, error) {
	if workosUserID == "" {
		return nil, ErrForbidden
	}
	if limit < 1 || limit > 100 {
		limit = 100
	}
	iterator := p.client.UserManagement().ListSessions(ctx, workosUserID, &workos.UserManagementListSessionsParams{
		PaginationParams: workos.PaginationParams{Limit: &limit},
	})
	sessions := make([]RemoteSession, 0, limit)
	for len(sessions) < limit && iterator.Next() {
		item := iterator.Current()
		if item == nil {
			continue
		}
		session, err := convertRemoteSession(*item)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	if err := iterator.Err(); err != nil {
		return nil, fmt.Errorf("auth: list WorkOS sessions: %w", err)
	}
	return sessions, nil
}

func convertRemoteSession(item workos.UserSessionsListItem) (RemoteSession, error) {
	session := RemoteSession{ID: item.ID, UserID: item.UserID, Status: string(item.Status)}
	if item.IPAddress != nil {
		session.IPAddress = *item.IPAddress
	}
	if item.UserAgent != nil {
		session.UserAgent = *item.UserAgent
	}
	var err error
	if session.ExpiresAt, err = time.Parse(time.RFC3339Nano, item.ExpiresAt); err != nil {
		return RemoteSession{}, fmt.Errorf("auth: parse WorkOS session expiration: %w", err)
	}
	if session.CreatedAt, err = time.Parse(time.RFC3339Nano, item.CreatedAt); err != nil {
		return RemoteSession{}, fmt.Errorf("auth: parse WorkOS session creation time: %w", err)
	}
	if session.UpdatedAt, err = time.Parse(time.RFC3339Nano, item.UpdatedAt); err != nil {
		return RemoteSession{}, fmt.Errorf("auth: parse WorkOS session update time: %w", err)
	}
	if item.EndedAt != nil {
		value, parseErr := time.Parse(time.RFC3339Nano, *item.EndedAt)
		if parseErr != nil {
			return RemoteSession{}, fmt.Errorf("auth: parse WorkOS session end time: %w", parseErr)
		}
		session.EndedAt = &value
	}
	return session, nil
}

func (s *AuthService) ListSessions(ctx context.Context, userID, actorID string, limit int) ([]RemoteSession, error) {
	if err := s.authorizeSessionOwner(ctx, userID, actorID); err != nil {
		return nil, err
	}
	directory, ok := s.provider.(SessionDirectory)
	if !ok {
		return nil, errors.New("auth: identity provider does not support session listing")
	}
	user, err := s.accounts.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return directory.ListSessions(ctx, user.WorkOSUserID, limit)
}

func (s *AuthService) authorizeSessionOwner(ctx context.Context, userID, actorID string) error {
	if actorID == "" {
		return ErrForbidden
	}
	if actorID == userID {
		return nil
	}
	actor, err := s.accounts.GetUserByID(ctx, actorID)
	if err != nil || actor.Role != accounts.RoleSuperadmin || !actor.State.CanAuthenticate() {
		return ErrForbidden
	}
	return nil
}
