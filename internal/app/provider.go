package app

import (
	"context"
	"errors"
	"sync"

	"arca/internal/accounts"
	"arca/internal/auth"
)

var ErrIdentityNotConfigured = errors.New("WorkOS identity provider is not configured")

type identityProvider interface {
	auth.Provider
	accounts.IdentityProvider
}

// DynamicProvider allows a first-run wizard to install validated WorkOS
// credentials without rebuilding the account and authentication services.
type DynamicProvider struct {
	mu       sync.RWMutex
	delegate identityProvider
}

func (p *DynamicProvider) Set(delegate identityProvider) {
	p.mu.Lock()
	p.delegate = delegate
	p.mu.Unlock()
}

func (p *DynamicProvider) get() (identityProvider, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.delegate == nil {
		return nil, ErrIdentityNotConfigured
	}
	return p.delegate, nil
}

func (p *DynamicProvider) ReconcileUser(ctx context.Context, request accounts.IdentityRequest) (accounts.ExternalIdentity, error) {
	delegate, err := p.get()
	if err != nil {
		return accounts.ExternalIdentity{}, err
	}
	return delegate.ReconcileUser(ctx, request)
}

func (p *DynamicProvider) SendMagic(ctx context.Context, request auth.MagicStartRequest) (auth.MagicChallenge, error) {
	delegate, err := p.get()
	if err != nil {
		return auth.MagicChallenge{}, err
	}
	return delegate.SendMagic(ctx, request)
}

func (p *DynamicProvider) VerifyMagic(ctx context.Context, request auth.MagicVerifyRequest) (auth.RemoteAuthentication, error) {
	delegate, err := p.get()
	if err != nil {
		return auth.RemoteAuthentication{}, err
	}
	return delegate.VerifyMagic(ctx, request)
}

func (p *DynamicProvider) SealSession(authentication auth.RemoteAuthentication, password string) (string, error) {
	delegate, err := p.get()
	if err != nil {
		return "", err
	}
	return delegate.SealSession(authentication, password)
}

func (p *DynamicProvider) InspectSession(sealed, password string) (auth.SessionInspection, error) {
	delegate, err := p.get()
	if err != nil {
		return auth.SessionInspection{}, err
	}
	return delegate.InspectSession(sealed, password)
}

func (p *DynamicProvider) RefreshSession(ctx context.Context, sealed, password string) (auth.SessionRefresh, error) {
	delegate, err := p.get()
	if err != nil {
		return auth.SessionRefresh{}, err
	}
	return delegate.RefreshSession(ctx, sealed, password)
}

func (p *DynamicProvider) RevokeSession(ctx context.Context, sessionID string) error {
	delegate, err := p.get()
	if err != nil {
		return err
	}
	return delegate.RevokeSession(ctx, sessionID)
}
