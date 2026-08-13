package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"arca/internal/accounts"

	workos "github.com/workos/workos-go/v10"
)

// WorkOSProvider is the production adapter for WorkOS User Management and the
// WorkOS sealed-session helpers.
type WorkOSProvider struct{ client *workos.Client }

func NewWorkOSProvider(apiKey, clientID string, options ...workos.ClientOption) (*WorkOSProvider, error) {
	if apiKey == "" || clientID == "" {
		return nil, errors.New("auth: WorkOS API key and client ID are required")
	}
	options = append(options, workos.WithClientID(clientID))
	return &WorkOSProvider{client: workos.NewClient(apiKey, options...)}, nil
}

// ReconcileUser implements accounts.IdentityProvider. It first looks up the
// stable Arca UUID as WorkOS external_id and only creates when absent, so an
// interrupted approval can be retried without duplicate identities.
func (p *WorkOSProvider) ReconcileUser(ctx context.Context, request accounts.IdentityRequest) (accounts.ExternalIdentity, error) {
	if request.ArcaUserID == "" || request.Email == "" {
		return accounts.ExternalIdentity{}, errors.New("auth: Arca user id and email are required")
	}
	user, err := p.client.UserManagement().GetByExternalID(ctx, request.ArcaUserID)
	if err == nil {
		return reconcileIdentity(user.ID, user.Email, user.ExternalID, request)
	}
	var notFound *workos.NotFoundError
	if !errors.As(err, &notFound) {
		return accounts.ExternalIdentity{}, fmt.Errorf("auth: look up WorkOS user by external id: %w", err)
	}
	name := request.DisplayName
	response, createErr := p.client.UserManagement().Create(ctx, &workos.UserManagementCreateParams{
		Email: request.Email, Name: optionalString(name), ExternalID: &request.ArcaUserID,
		Metadata: map[string]string{"arca_user_id": request.ArcaUserID},
	})
	if createErr != nil {
		// A lost successful response or concurrent retry can surface as a
		// conflict. Re-read by external id before reporting the failure.
		user, getErr := p.client.UserManagement().GetByExternalID(ctx, request.ArcaUserID)
		if getErr == nil {
			return reconcileIdentity(user.ID, user.Email, user.ExternalID, request)
		}
		return accounts.ExternalIdentity{}, fmt.Errorf("auth: create WorkOS user: %w", createErr)
	}
	return reconcileIdentity(response.ID, response.Email, response.ExternalID, request)
}

func reconcileIdentity(id, email string, externalID *string, request accounts.IdentityRequest) (accounts.ExternalIdentity, error) {
	if externalID == nil || *externalID != request.ArcaUserID {
		return accounts.ExternalIdentity{}, errors.New("auth: WorkOS external id mismatch")
	}
	_, expected, err := accounts.NormalizeEmail(request.Email)
	if err != nil {
		return accounts.ExternalIdentity{}, err
	}
	_, actual, err := accounts.NormalizeEmail(email)
	if err != nil || actual != expected {
		return accounts.ExternalIdentity{}, errors.New("auth: WorkOS email mismatch")
	}
	return accounts.ExternalIdentity{ID: id, Email: email}, nil
}

func (p *WorkOSProvider) SendMagic(ctx context.Context, request MagicStartRequest) (MagicChallenge, error) {
	response, err := p.client.UserManagement().CreateMagicAuth(ctx, &workos.UserManagementCreateMagicAuthParams{
		Email: request.Email, IPAddress: optionalString(request.IPAddress),
		UserAgent:          optionalString(request.UserAgent),
		RadarAuthAttemptID: optionalString(request.RadarAuthAttemptID),
		SignalsID:          optionalString(request.SignalsID),
	})
	if err != nil {
		return MagicChallenge{}, fmt.Errorf("auth: create WorkOS Magic Auth challenge: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, response.ExpiresAt)
	if err != nil {
		expiresAt, err = time.Parse(time.RFC3339Nano, response.ExpiresAt)
	}
	if err != nil {
		return MagicChallenge{}, fmt.Errorf("auth: parse WorkOS challenge expiration: %w", err)
	}
	radar := ""
	if response.RadarAuthAttemptID != nil {
		radar = *response.RadarAuthAttemptID
	}
	// WorkOS includes the code in its server-side API response. Arca
	// intentionally discards it here; it must never reach React or logs.
	return MagicChallenge{
		ID: response.ID, UserID: response.UserID, Email: response.Email,
		ExpiresAt: expiresAt.UTC(), RadarAuthAttemptID: radar,
	}, nil
}

func (p *WorkOSProvider) VerifyMagic(ctx context.Context, request MagicVerifyRequest) (RemoteAuthentication, error) {
	response, err := p.client.UserManagement().AuthenticateWithMagicAuth(ctx, &workos.UserManagementAuthenticateWithMagicAuthParams{
		Code: request.Code, Email: request.Email,
		IPAddress: optionalString(request.IPAddress), UserAgent: optionalString(request.UserAgent),
		RadarAuthAttemptID: optionalString(request.RadarAuthAttemptID),
	})
	if err != nil {
		return RemoteAuthentication{}, fmt.Errorf("auth: verify WorkOS Magic Auth: %w", err)
	}
	if response.User == nil || response.User.ID == "" {
		return RemoteAuthentication{}, errors.New("auth: WorkOS authentication returned no user")
	}
	return RemoteAuthentication{
		WorkOSUserID: response.User.ID, Email: response.User.Email,
		AccessToken: response.AccessToken, RefreshToken: response.RefreshToken,
		RawUser: response.User, Impersonator: response.Impersonator,
	}, nil
}

func (p *WorkOSProvider) SealSession(authentication RemoteAuthentication, password string) (string, error) {
	user, ok := authentication.RawUser.(*workos.User)
	if !ok || user == nil {
		user = &workos.User{ID: authentication.WorkOSUserID, Email: authentication.Email}
	}
	var impersonator *workos.AuthenticateResponseImpersonator
	if authentication.Impersonator != nil {
		impersonator, _ = authentication.Impersonator.(*workos.AuthenticateResponseImpersonator)
	}
	sealed, err := workos.SealSessionFromAuthResponse(
		authentication.AccessToken, authentication.RefreshToken, user, impersonator, password,
	)
	if err != nil {
		return "", fmt.Errorf("auth: seal WorkOS session: %w", err)
	}
	return sealed, nil
}

func (p *WorkOSProvider) InspectSession(sealed, password string) (SessionInspection, error) {
	result, err := workos.AuthenticateSession(sealed, password)
	if err != nil {
		return SessionInspection{}, fmt.Errorf("auth: inspect WorkOS session: %w", err)
	}
	inspection := SessionInspection{
		Authenticated: result.Authenticated, NeedsRefresh: result.NeedsRefresh,
		SessionID: result.SessionID, Reason: result.Reason,
	}
	if result.User != nil {
		inspection.WorkOSUserID = result.User.ID
	}
	return inspection, nil
}

func (p *WorkOSProvider) RefreshSession(ctx context.Context, sealed, password string) (SessionRefresh, error) {
	result, err := p.client.RefreshSession(ctx, sealed, password)
	if err != nil {
		terminal := result != nil && result.Reason == "refresh_token_revoked"
		reason := "refresh_failed"
		if result != nil && result.Reason != "" {
			reason = result.Reason
		}
		return SessionRefresh{Terminal: terminal, Reason: reason}, err
	}
	if result == nil || !result.Authenticated {
		reason := "refresh_failed"
		if result != nil && result.Reason != "" {
			reason = result.Reason
		}
		return SessionRefresh{Terminal: reason == "refresh_token_revoked", Reason: reason}, nil
	}
	inspection, inspectErr := p.InspectSession(result.SealedSession, password)
	if inspectErr != nil {
		return SessionRefresh{}, inspectErr
	}
	return SessionRefresh{
		Authenticated: inspection.Authenticated, SealedSession: result.SealedSession,
		WorkOSUserID: inspection.WorkOSUserID, SessionID: inspection.SessionID,
		Reason: inspection.Reason,
	}, nil
}

func (p *WorkOSProvider) RevokeSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return ErrUnauthenticated
	}
	if err := p.client.UserManagement().RevokeSession(ctx, &workos.UserManagementRevokeSessionParams{SessionID: sessionID}); err != nil {
		return fmt.Errorf("auth: revoke WorkOS session: %w", err)
	}
	return nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
