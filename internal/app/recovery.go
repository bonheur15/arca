package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"arca/internal/accounts"
	"arca/internal/audit"
	"arca/internal/config"

	"github.com/google/uuid"
)

// CreateRecoveryCode issues a terminal-only one-use credential. Only its HMAC
// is stored. The plaintext must be shown exactly once by the CLI.
func (r *Runtime) CreateRecoveryCode(ctx context.Context) (string, time.Time, error) {
	key, err := config.DecodeSecret(r.Config.Secrets.StatusHMACKey)
	if err != nil {
		return "", time.Time{}, err
	}
	random := make([]byte, 20)
	if _, err := rand.Read(random); err != nil {
		return "", time.Time{}, err
	}
	code := "ARCA-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random)
	hash := recoveryHash(key, code)
	id, err := uuid.NewV7()
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(15 * time.Minute)
	if _, err := r.Database.Writer().ExecContext(ctx, `INSERT INTO admin_recovery_codes(id, code_hash, expires_at, created_at) VALUES(?,?,?,?)`, id.String(), hash, expires.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return "", time.Time{}, err
	}
	_ = r.Audit.Record(ctx, audit.Event{Action: "recovery.code_generated", TargetType: "recovery_code", TargetID: id.String()})
	return code, expires, nil
}

// AddRecoverySuperadmin promotes an existing active identity or provisions a
// new one after consuming a one-use recovery code. It intentionally requires
// local data-directory access through the CLI in addition to the code itself.
func (r *Runtime) AddRecoverySuperadmin(ctx context.Context, code, username, email, displayName string, quotaBytes int64) (*accounts.User, error) {
	if strings.TrimSpace(code) == "" {
		return nil, errors.New("recovery code is required")
	}
	key, err := config.DecodeSecret(r.Config.Secrets.StatusHMACKey)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	result, err := r.Database.Writer().ExecContext(ctx, `UPDATE admin_recovery_codes SET consumed_at = ?
		WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ?`, now.Format(time.RFC3339Nano), recoveryHash(key, code), now.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		return nil, errors.New("recovery code is invalid, expired, or already used")
	}
	mutation := accounts.MutationContext{}
	if existing, lookupErr := r.AccountRepo.GetUserByUsernameOrEmail(ctx, email); lookupErr == nil {
		if !existing.State.CanAuthenticate() {
			return nil, errors.New("the existing account must be restored before promotion")
		}
		promoted, promoteErr := r.AccountRepo.SetRole(ctx, existing.ID, accounts.RoleSuperadmin)
		if promoteErr != nil {
			return nil, promoteErr
		}
		_ = r.Audit.Record(ctx, audit.Event{Action: "recovery.superadmin_promoted", TargetType: "user", TargetID: promoted.ID})
		return promoted, nil
	} else if !errors.Is(lookupErr, accounts.ErrNotFound) {
		return nil, lookupErr
	}
	created, err := r.AccountRepo.CreateUser(ctx, accounts.CreateUserParams{Username: username, Email: email, DisplayName: displayName, Role: accounts.RoleSuperadmin, State: accounts.StateProvisioning, QuotaBytes: quotaBytes, Policy: accounts.DefaultPolicy()})
	if err != nil {
		return nil, err
	}
	created, err = r.Accounts.ResumeProvisioning(ctx, created.ID, mutation)
	if err != nil {
		return created, fmt.Errorf("recovery superadmin remains provisioning: %w", err)
	}
	_ = r.Audit.Record(ctx, audit.Event{Action: "recovery.superadmin_created", TargetType: "user", TargetID: created.ID})
	return created, nil
}

func recoveryHash(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("arca:admin-recovery:v1\x00"))
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}
