package accounts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"arca/internal/audit"
)

type IdentityRequest struct {
	ArcaUserID  string
	Email       string
	DisplayName string
}

type ExternalIdentity struct {
	ID    string
	Email string
}

// IdentityProvider reconciles an Arca provisioning record with an external
// identity. Implementations must be idempotent by ArcaUserID.
type IdentityProvider interface {
	ReconcileUser(context.Context, IdentityRequest) (ExternalIdentity, error)
}

type Service struct {
	repository *Repository
	identity   IdentityProvider
	status     *StatusTokenCodec
	audit      audit.Recorder
	now        func() time.Time
}

func NewService(repository *Repository, identity IdentityProvider, status *StatusTokenCodec, recorder audit.Recorder) *Service {
	if recorder == nil {
		recorder = audit.NopRecorder{}
	}
	return &Service{repository: repository, identity: identity, status: status, audit: recorder, now: time.Now}
}

type RequestAccessResult struct {
	Request     AccessRequest
	StatusToken string
}

func (s *Service) RequestAccess(ctx context.Context, params CreateAccessRequestParams, mutation MutationContext) (*RequestAccessResult, error) {
	if s.status == nil {
		return nil, errors.New("accounts: status token codec is required")
	}
	token, hash, err := s.status.Generate()
	if err != nil {
		return nil, fmt.Errorf("accounts: generate request status token: %w", err)
	}
	request, err := s.repository.CreateAccessRequest(ctx, params, hash)
	if err != nil {
		return nil, err
	}
	if err := s.record(ctx, mutation, "access_request.created", "access_request", request.ID, nil); err != nil {
		return nil, err
	}
	return &RequestAccessResult{Request: *request, StatusToken: token}, nil
}

func (s *Service) RequestStatus(ctx context.Context, statusToken string) (*AccessRequest, error) {
	if s.status == nil || statusToken == "" {
		return nil, ErrInvalidStatusToken
	}
	return s.repository.GetAccessRequestByStatusToken(ctx, s.status.Hash(statusToken))
}

func (s *Service) BootstrapSuperadmin(ctx context.Context, params CreateUserParams, mutation MutationContext) (*User, error) {
	count, err := s.repository.CountUsers(ctx)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		return nil, ErrForbidden
	}
	params.Role = RoleSuperadmin
	return s.provision(ctx, params, mutation, "user.bootstrap_created")
}

func (s *Service) CreateUser(ctx context.Context, params CreateUserParams, mutation MutationContext) (*User, error) {
	if err := s.requireSuperadmin(ctx, mutation.ActorID); err != nil {
		return nil, err
	}
	if !params.Role.Valid() {
		params.Role = RoleMember
	}
	return s.provision(ctx, params, mutation, "user.created")
}

func (s *Service) provision(ctx context.Context, params CreateUserParams, mutation MutationContext, action string) (*User, error) {
	if s.identity == nil {
		return nil, errors.New("accounts: identity provider is required")
	}
	params.State = StateProvisioning
	user, err := s.repository.CreateUser(ctx, params)
	if err != nil {
		return nil, err
	}
	completed, err := s.reconcile(ctx, user)
	if err != nil {
		return user, err
	}
	if err := s.record(ctx, mutation, action, "user", completed.ID, map[string]any{"role": completed.Role}); err != nil {
		return completed, err
	}
	return completed, nil
}

// ResumeProvisioning safely retries a failed WorkOS boundary using the stable
// local UUID as the external identity key.
func (s *Service) ResumeProvisioning(ctx context.Context, userID string, mutation MutationContext) (*User, error) {
	if mutation.ActorID != "" {
		if err := s.requireSuperadmin(ctx, mutation.ActorID); err != nil {
			return nil, err
		}
	}
	user, err := s.repository.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user.State != StateProvisioning {
		return nil, ErrInvalidTransition
	}
	completed, err := s.reconcile(ctx, user)
	if err != nil {
		return user, err
	}
	if err := s.record(ctx, mutation, "user.provisioning_resumed", "user", userID, nil); err != nil {
		return completed, err
	}
	return completed, nil
}

func (s *Service) reconcile(ctx context.Context, user *User) (*User, error) {
	identity, err := s.identity.ReconcileUser(ctx, IdentityRequest{
		ArcaUserID: user.ID, Email: user.Email, DisplayName: user.DisplayName,
	})
	if err != nil {
		return nil, fmt.Errorf("accounts: reconcile external identity for %s: %w", user.ID, err)
	}
	_, expectedEmail, _ := NormalizeEmail(user.Email)
	_, actualEmail, normalizeErr := NormalizeEmail(identity.Email)
	if normalizeErr != nil || identity.ID == "" || actualEmail != expectedEmail {
		return nil, errors.New("accounts: identity provider returned a mismatched identity")
	}
	return s.repository.CompleteProvisioning(ctx, user.ID, identity.ID)
}

func (s *Service) ApproveAccessRequest(ctx context.Context, params ReserveApprovalParams, note string, mutation MutationContext) (*User, error) {
	if err := s.requireSuperadmin(ctx, mutation.ActorID); err != nil {
		return nil, err
	}
	if s.identity == nil {
		return nil, errors.New("accounts: identity provider is required")
	}
	user, err := s.repository.ReserveAccessRequestApproval(ctx, params)
	if err != nil {
		return nil, err
	}
	if user.State == StateProvisioning {
		user, err = s.reconcile(ctx, user)
		if err != nil {
			return user, err
		}
	}
	if _, err := s.repository.FinalizeAccessRequestApproval(ctx, params.RequestID, user.ID, mutation.ActorID, note); err != nil {
		return user, err
	}
	if err := s.record(ctx, mutation, "access_request.approved", "access_request", params.RequestID, map[string]any{"user_id": user.ID}); err != nil {
		return user, err
	}
	return user, nil
}

func (s *Service) RejectAccessRequest(ctx context.Context, requestID, note string, mutation MutationContext) (*AccessRequest, error) {
	if err := s.requireSuperadmin(ctx, mutation.ActorID); err != nil {
		return nil, err
	}
	request, err := s.repository.RejectAccessRequest(ctx, requestID, mutation.ActorID, note)
	if err != nil {
		return nil, err
	}
	if err := s.record(ctx, mutation, "access_request.rejected", "access_request", requestID, nil); err != nil {
		return request, err
	}
	return request, nil
}

func (s *Service) SetRole(ctx context.Context, userID string, role Role, mutation MutationContext) (*User, error) {
	if err := s.requireSuperadmin(ctx, mutation.ActorID); err != nil {
		return nil, err
	}
	user, err := s.repository.SetRole(ctx, userID, role)
	if err != nil {
		return nil, err
	}
	if err := s.record(ctx, mutation, "user.role_changed", "user", userID, map[string]any{"role": role}); err != nil {
		return user, err
	}
	return user, nil
}

func (s *Service) SuspendUser(ctx context.Context, userID string, mutation MutationContext) (*User, error) {
	return s.setState(ctx, userID, StateSuspended, nil, "user.suspended", mutation)
}

func (s *Service) ScheduleDeletion(ctx context.Context, userID string, mutation MutationContext) (*User, error) {
	due := s.now().UTC().Add(7 * 24 * time.Hour)
	return s.setState(ctx, userID, StateDeletionPending, &due, "user.deletion_scheduled", mutation)
}

func (s *Service) setState(ctx context.Context, userID string, state State, due *time.Time, action string, mutation MutationContext) (*User, error) {
	if err := s.requireSuperadmin(ctx, mutation.ActorID); err != nil {
		return nil, err
	}
	user, err := s.repository.SetState(ctx, userID, state, due)
	if err != nil {
		return nil, err
	}
	if err := s.record(ctx, mutation, action, "user", userID, nil); err != nil {
		return user, err
	}
	return user, nil
}

func (s *Service) RestoreUser(ctx context.Context, userID string, mutation MutationContext) (*User, error) {
	if err := s.requireSuperadmin(ctx, mutation.ActorID); err != nil {
		return nil, err
	}
	user, err := s.repository.RestoreUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := s.record(ctx, mutation, "user.restored", "user", userID, nil); err != nil {
		return user, err
	}
	return user, nil
}

func (s *Service) UpdatePolicyAndQuota(ctx context.Context, userID string, quotaBytes int64, quotaUnlimited bool, policy Policy, mutation MutationContext) (*User, error) {
	if err := s.requireSuperadmin(ctx, mutation.ActorID); err != nil {
		return nil, err
	}
	user, err := s.repository.UpdatePolicyAndQuota(ctx, userID, quotaBytes, quotaUnlimited, policy)
	if err != nil {
		return nil, err
	}
	if err := s.record(ctx, mutation, "user.policy_changed", "user", userID, map[string]any{"quota_bytes": quotaBytes, "quota_unlimited": quotaUnlimited}); err != nil {
		return user, err
	}
	return user, nil
}

func (s *Service) UpdatePreferences(ctx context.Context, userID string, preferences Preferences, mutation MutationContext) (*User, error) {
	if mutation.ActorID == "" {
		return nil, ErrForbidden
	}
	if mutation.ActorID != userID {
		if err := s.requireSuperadmin(ctx, mutation.ActorID); err != nil {
			return nil, err
		}
	}
	user, err := s.repository.UpdatePreferences(ctx, userID, preferences)
	if err != nil {
		return nil, err
	}
	if err := s.record(ctx, mutation, "user.preferences_changed", "user", userID, nil); err != nil {
		return user, err
	}
	return user, nil
}

func (s *Service) requireSuperadmin(ctx context.Context, actorID string) error {
	if strings.TrimSpace(actorID) == "" {
		return ErrForbidden
	}
	actor, err := s.repository.GetUserByID(ctx, actorID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrForbidden
		}
		return err
	}
	if actor.Role != RoleSuperadmin || !actor.State.CanAuthenticate() {
		return ErrForbidden
	}
	return nil
}

func (s *Service) record(ctx context.Context, mutation MutationContext, action, targetType, targetID string, metadata map[string]any) error {
	var actorID *string
	if mutation.ActorID != "" {
		actor := mutation.ActorID
		actorID = &actor
	}
	return s.audit.Record(ctx, audit.Event{
		ActorID: actorID, Action: action, TargetType: targetType, TargetID: targetID,
		IPAddress: mutation.IPAddress, UserAgent: mutation.UserAgent,
		RequestID: mutation.RequestID, Metadata: metadata,
	})
}
