package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"arca/internal/accounts"
	"arca/internal/auth"
	"arca/internal/config"
)

type Bootstrap struct {
	mu       sync.Mutex
	codeHash [32]byte
	expires  time.Time
	pending  *bootstrapPending
	config   *config.Runtime
	db       *sql.DB
	accounts *accounts.Service
	auth     *auth.AuthService
	provider *DynamicProvider
	logger   *slog.Logger
	now      func() time.Time
}

type bootstrapPending struct {
	Input          BootstrapConfigureInput
	ChallengeToken string
	ExpiresAt      time.Time
}

type BootstrapConfigureInput struct {
	SetupCode       string `json:"setup_code"`
	InstanceName    string `json:"instance_name"`
	PublicURL       string `json:"public_url"`
	WorkOSClientID  string `json:"workos_client_id"`
	WorkOSAPIKey    string `json:"workos_api_key"`
	Username        string `json:"username"`
	Email           string `json:"email"`
	DisplayName     string `json:"display_name"`
	QuotaBytes      int64  `json:"quota_bytes"`
	QuotaUnlimited  bool   `json:"quota_unlimited"`
}

type BootstrapStatus struct {
	Initialized   bool      `json:"initialized"`
	SetupRequired bool      `json:"setup_required"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
}

func NewBootstrap(runtime *config.Runtime, db *sql.DB, accountService *accounts.Service, authService *auth.AuthService, provider *DynamicProvider, initialized bool, logger *slog.Logger) (*Bootstrap, string, error) {
	bootstrap := &Bootstrap{config: runtime, db: db, accounts: accountService, auth: authService, provider: provider, logger: logger, now: time.Now}
	if initialized {
		return bootstrap, "", nil
	}
	code, err := randomSetupCode(20)
	if err != nil {
		return nil, "", err
	}
	bootstrap.codeHash = sha256.Sum256([]byte(code))
	bootstrap.expires = bootstrap.now().UTC().Add(30 * time.Minute)
	return bootstrap, code, nil
}

func (b *Bootstrap) Status(ctx context.Context) (BootstrapStatus, error) {
	initialized, err := b.initialized(ctx)
	if err != nil {
		return BootstrapStatus{}, err
	}
	b.mu.Lock()
	expires := b.expires
	b.mu.Unlock()
	return BootstrapStatus{Initialized: initialized, SetupRequired: !initialized, ExpiresAt: expires}, nil
}

// Configure validates the console code, persists the operator configuration,
// creates the initial identity, and starts its WorkOS Magic Auth challenge.
// The database remains uninitialized until Verify succeeds.
func (b *Bootstrap) Configure(ctx context.Context, input BootstrapConfigureInput, remoteIP, userAgent string) (time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.accounts == nil || b.auth == nil || b.provider == nil {
		return time.Time{}, errors.New("bootstrap services are not configured")
	}
	if b.now().After(b.expires) || !equalHash(b.codeHash[:], hashString(input.SetupCode)) {
		return time.Time{}, errors.New("invalid or expired setup code")
	}
	if input.QuotaBytes < 0 {
		return time.Time{}, errors.New("quota must not be negative")
	}
	previousFile := b.config.File
	previousSecrets := b.config.Secrets
	b.config.File.InstanceName = input.InstanceName
	b.config.File.PublicURL = input.PublicURL
	b.config.File.WorkOSClientID = input.WorkOSClientID
	b.config.Secrets.WorkOSAPIKey = input.WorkOSAPIKey
	if err := b.config.EnsureSecrets(); err != nil {
		b.config.File, b.config.Secrets = previousFile, previousSecrets
		return time.Time{}, err
	}
	if err := b.config.ValidateConfigured(); err != nil {
		b.config.File, b.config.Secrets = previousFile, previousSecrets
		return time.Time{}, err
	}
	workosProvider, err := auth.NewWorkOSProvider(input.WorkOSAPIKey, input.WorkOSClientID)
	if err != nil {
		b.config.File, b.config.Secrets = previousFile, previousSecrets
		return time.Time{}, err
	}
	b.provider.Set(workosProvider)
	mutation := accounts.MutationContext{IPAddress: remoteIP, UserAgent: userAgent}
	var existingID, existingUsername, existingEmail, existingState string
	err = b.db.QueryRowContext(ctx, `SELECT id, username_key, email_key, state FROM users ORDER BY created_at LIMIT 1`).
		Scan(&existingID, &existingUsername, &existingEmail, &existingState)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = b.accounts.BootstrapSuperadmin(ctx, accounts.CreateUserParams{
			Username: input.Username, Email: input.Email, DisplayName: input.DisplayName,
			QuotaBytes: input.QuotaBytes, QuotaUnlimited: input.QuotaUnlimited, Policy: accounts.DefaultPolicy(),
		}, mutation)
	} else if err == nil {
		_, usernameKey, usernameErr := accounts.NormalizeUsername(input.Username)
		_, emailKey, emailErr := accounts.NormalizeEmail(input.Email)
		if usernameErr != nil || emailErr != nil || usernameKey != existingUsername || emailKey != existingEmail {
			err = errors.New("bootstrap identity does not match the existing resumable setup")
		} else if existingState == string(accounts.StateProvisioning) {
			_, err = b.accounts.ResumeProvisioning(ctx, existingID, mutation)
		} else if existingState != string(accounts.StateActive) {
			err = errors.New("existing bootstrap identity is not active")
		}
	}
	if err != nil {
		b.config.File, b.config.Secrets = previousFile, previousSecrets
		return time.Time{}, fmt.Errorf("create bootstrap identity: %w", err)
	}
	challenge, err := b.auth.StartMagic(ctx, auth.MagicStartRequest{Email: input.Email, IPAddress: remoteIP, UserAgent: userAgent})
	if err != nil {
		return time.Time{}, fmt.Errorf("start bootstrap authentication: %w", err)
	}
	b.pending = &bootstrapPending{Input: input, ChallengeToken: challenge.ChallengeToken, ExpiresAt: challenge.ExpiresAt}
	return challenge.ExpiresAt, nil
}

func (b *Bootstrap) Verify(ctx context.Context, setupCode, magicCode string) (*auth.MagicVerifyResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.now().After(b.expires) || !equalHash(b.codeHash[:], hashString(setupCode)) || b.pending == nil {
		return nil, errors.New("invalid or expired setup state")
	}
	result, err := b.auth.VerifyMagic(ctx, b.pending.ChallengeToken, magicCode)
	if err != nil {
		return nil, err
	}
	if err := b.setInitialized(ctx, true); err != nil {
		return nil, err
	}
	if err := b.config.Save(); err != nil {
		_ = b.setInitialized(ctx, false)
		return nil, err
	}
	b.codeHash = [32]byte{}
	b.expires = time.Time{}
	b.pending = nil
	return result, nil
}

func (b *Bootstrap) initialized(ctx context.Context) (bool, error) {
	if b.db == nil {
		return false, errors.New("bootstrap database is not configured")
	}
	var initialized int
	err := b.db.QueryRowContext(ctx, `SELECT initialized FROM instance_settings WHERE singleton = 1`).Scan(&initialized)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return initialized == 1, err
}

func (b *Bootstrap) setInitialized(ctx context.Context, initialized bool) error {
	value := 0
	if initialized {
		value = 1
	}
	now := b.now().UTC().Format(time.RFC3339Nano)
	result, err := b.db.ExecContext(ctx, `UPDATE instance_settings SET initialized = ?, name = ?, public_url = ?, filesystem_reserve_bytes = ?, updated_at = ? WHERE singleton = 1`,
		value, b.config.File.InstanceName, b.config.File.PublicURL, b.config.File.FilesystemReserveBytes, now)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("instance settings row is missing")
	}
	return nil
}

func randomSetupCode(length int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	random := make([]byte, length)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	for index := range random {
		random[index] = alphabet[int(random[index])%len(alphabet)]
	}
	return string(random), nil
}

func hashString(value string) []byte {
	hash := sha256.Sum256([]byte(value))
	return hash[:]
}

func equalHash(first, second []byte) bool {
	if len(first) != len(second) {
		return false
	}
	var result byte
	for index := range first {
		result |= first[index] ^ second[index]
	}
	return result == 0
}
