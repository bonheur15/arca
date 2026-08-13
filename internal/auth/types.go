// Package auth implements Arca's WorkOS-backed Magic Auth flow, sealed browser
// sessions, CSRF protection, and personal access tokens.
package auth

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("auth: invalid or expired credentials")
	ErrUnauthenticated    = errors.New("auth: session is not authenticated")
	ErrSessionUnavailable = errors.New("auth: session provider is temporarily unavailable")
	ErrForbidden          = errors.New("auth: forbidden")
	ErrInvalidCSRF        = errors.New("auth: invalid csrf token")
	ErrInvalidToken       = errors.New("auth: invalid access token")
	ErrTokenPolicy        = errors.New("auth: personal access tokens are disabled")
	ErrRateLimited        = errors.New("auth: too many attempts")
)

type MagicStartRequest struct {
	Email              string
	IPAddress          string
	UserAgent          string
	RadarAuthAttemptID string
	SignalsID          string
}

type MagicChallenge struct {
	ID                 string
	UserID             string
	Email              string
	ExpiresAt          time.Time
	RadarAuthAttemptID string
}

type MagicVerifyRequest struct {
	Email              string
	Code               string
	IPAddress          string
	UserAgent          string
	RadarAuthAttemptID string
}

type RemoteAuthentication struct {
	WorkOSUserID string
	Email        string
	AccessToken  string
	RefreshToken string
	SessionID    string
	RawUser      any
	Impersonator any
}

type SessionInspection struct {
	Authenticated bool
	NeedsRefresh  bool
	WorkOSUserID  string
	SessionID     string
	Reason        string
}

type SessionRefresh struct {
	Authenticated bool
	Terminal      bool
	SealedSession string
	WorkOSUserID  string
	SessionID     string
	Reason        string
}

// Provider is deliberately small enough to fake. The WorkOS implementation
// wraps workos-go v10 and never exposes Magic Auth codes to callers.
type Provider interface {
	SendMagic(context.Context, MagicStartRequest) (MagicChallenge, error)
	VerifyMagic(context.Context, MagicVerifyRequest) (RemoteAuthentication, error)
	SealSession(RemoteAuthentication, string) (string, error)
	InspectSession(string, string) (SessionInspection, error)
	RefreshSession(context.Context, string, string) (SessionRefresh, error)
	RevokeSession(context.Context, string) error
}

type Challenge struct {
	ID                 string
	EmailKey           string
	MagicAuthID        string
	RadarAuthAttemptID string
	OriginalIPAddress  string
	OriginalUserAgent  string
	ExpiresAt          time.Time
	ConsumedAt         *time.Time
	CreatedAt          time.Time
}
