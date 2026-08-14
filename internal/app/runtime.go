package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"arca/internal/accounts"
	"arca/internal/audit"
	"arca/internal/auth"
	"arca/internal/backup"
	"arca/internal/config"
	"arca/internal/database"
	"arca/internal/files"
	"arca/internal/jobs"
	"arca/internal/shares"
	"arca/internal/uploads"
	"arca/migrations"

	"github.com/google/uuid"
)

// Runtime owns all process-scoped Arca dependencies. Closing it releases the
// SQLite pools and the exclusive data-directory lock in a deterministic order.
type Runtime struct {
	Config          *config.Runtime
	Database        *database.DB
	Accounts        *accounts.Service
	AccountRepo     *accounts.Repository
	Authentication  *auth.AuthService
	IdentityEvents  *auth.EventReconciler
	Tokens          *auth.TokenService
	Files           *files.Service
	Uploads         *uploads.Service
	Storage         *uploads.LocalStorage
	Shares          *shares.Service
	Jobs            *jobs.Runner
	Backup          *backup.Service
	Bootstrap       *Bootstrap
	Provider        *DynamicProvider
	Audit           audit.Recorder
	CookiePolicy    auth.CookiePolicy
	CSRFSecret      []byte
	SetupCode       string
	SQLiteVersion   string
	Version         string
	logger          *slog.Logger
	lock            *config.Lock
	closeOnce       sync.Once
	backgroundStop  context.CancelFunc
	backgroundGroup sync.WaitGroup
}

// Open constructs the complete single-node runtime without starting a network
// listener. This makes doctor, tests, and the HTTP command share one startup
// path and the same safety checks.
func Open(ctx context.Context, cfg config.Runtime, version string, logger *slog.Logger) (*Runtime, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := config.EnsureLayout(cfg.Layout); err != nil {
		return nil, err
	}
	lock, err := config.AcquireLock(cfg.Layout.LockFile)
	if err != nil {
		return nil, err
	}
	fail := func(cause error) (*Runtime, error) {
		_ = lock.Close()
		return nil, cause
	}
	if err := cfg.EnsureSecrets(); err != nil {
		return fail(err)
	}
	// Persist generated process secrets immediately so setup challenges remain
	// verifiable across ordinary restarts. Environment-injected secrets are
	// deliberately omitted by config.Save.
	if err := cfg.Save(); err != nil {
		return fail(err)
	}
	db, err := database.Open(ctx, database.Config{Path: cfg.Layout.Database, Migrations: migrations.Files})
	if err != nil {
		return fail(err)
	}
	cleanup := func(cause error) (*Runtime, error) {
		_ = db.Close()
		_ = lock.Close()
		return nil, cause
	}
	initialized, err := ensureInstanceRow(ctx, db, cfg)
	if err != nil {
		return cleanup(err)
	}
	if initialized {
		if err := loadInstanceSettings(ctx, db, &cfg); err != nil {
			return cleanup(err)
		}
		if err := cfg.Save(); err != nil {
			return cleanup(err)
		}
	}
	cookieKey, err := config.DecodeSecret(cfg.Secrets.CookieKey)
	if err != nil {
		return cleanup(fmt.Errorf("decode cookie secret: %w", err))
	}
	codeKey, err := config.DecodeSecret(cfg.Secrets.CodeHMACKey)
	if err != nil {
		return cleanup(fmt.Errorf("decode code secret: %w", err))
	}
	statusKey, err := config.DecodeSecret(cfg.Secrets.StatusHMACKey)
	if err != nil {
		return cleanup(fmt.Errorf("decode status secret: %w", err))
	}

	recorder := audit.NewSQLRecorder(db.Writer())
	repository := accounts.NewRepository(db.Writer())
	statusCodec, err := accounts.NewStatusTokenCodec(statusKey)
	if err != nil {
		return cleanup(err)
	}
	dynamicProvider := &DynamicProvider{}
	if cfg.Secrets.WorkOSAPIKey != "" && cfg.File.WorkOSClientID != "" {
		provider, providerErr := auth.NewWorkOSProvider(cfg.Secrets.WorkOSAPIKey, cfg.File.WorkOSClientID)
		if providerErr != nil {
			return cleanup(providerErr)
		}
		dynamicProvider.Set(provider)
	}
	accountService := accounts.NewService(repository, dynamicProvider, statusCodec, recorder)
	challengeStore, err := auth.NewChallengeStore(db.Writer(), statusKey)
	if err != nil {
		return cleanup(err)
	}
	authService, err := auth.NewService(repository, challengeStore, dynamicProvider, db.Writer(), cfg.Secrets.CookieKey, cookieKey, recorder)
	if err != nil {
		return cleanup(err)
	}
	tokenService, err := auth.NewTokenService(db.Writer(), repository, statusKey, recorder)
	if err != nil {
		return cleanup(err)
	}
	eventReconciler, err := auth.NewEventReconciler(db.Writer(), repository, authService, dynamicProvider, recorder)
	if err != nil {
		return cleanup(err)
	}
	fileService := files.NewService(db, files.ServiceOptions{})
	storage, err := uploads.NewLocalStorage(cfg.Layout.Root)
	if err != nil {
		return cleanup(err)
	}
	uploadService := uploads.NewService(db, storage, uploads.ServiceOptions{})
	shareService, err := shares.New(db.Writer(), codeKey)
	if err != nil {
		return cleanup(err)
	}
	jobRunner := jobs.New(db.Writer(), logger)
	registerJobs(jobRunner, db, uploadService, fileService)
	bootstrapService, setupCode, err := NewBootstrap(&cfg, db.Writer(), accountService, authService, dynamicProvider, initialized, logger)
	if err != nil {
		return cleanup(err)
	}
	secureCookies := cfg.TLSCert != ""
	if parsed, parseErr := url.Parse(cfg.File.PublicURL); parseErr == nil && parsed.Scheme == "https" {
		secureCookies = true
	}
	runtime := &Runtime{
		Config: &cfg, Database: db, Accounts: accountService, AccountRepo: repository,
		Authentication: authService, IdentityEvents: eventReconciler, Tokens: tokenService, Files: fileService,
		Uploads: uploadService, Storage: storage, Shares: shareService,
		Jobs: jobRunner, Backup: backup.New(db.Writer(), backup.Layout{Database: cfg.Layout.Database, BlobDir: cfg.Layout.BlobDir}, version),
		Bootstrap: bootstrapService, Provider: dynamicProvider, Audit: recorder,
		CookiePolicy: auth.DefaultCookiePolicy(secureCookies), CSRFSecret: cookieKey,
		SetupCode: setupCode, SQLiteVersion: db.SQLiteVersion(), Version: version,
		logger: logger, lock: lock,
	}
	return runtime, nil
}

func ensureInstanceRow(ctx context.Context, db *database.DB, cfg config.Runtime) (bool, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return false, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = db.Writer().ExecContext(ctx, `INSERT INTO instance_settings
		(singleton, instance_id, initialized, name, public_url, filesystem_reserve_bytes, trusted_proxy_cidrs, created_at, updated_at)
		VALUES (1, ?, 0, ?, ?, ?, '[]', ?, ?) ON CONFLICT(singleton) DO NOTHING`,
		id.String(), cfg.File.InstanceName, cfg.File.PublicURL, cfg.File.FilesystemReserveBytes, now, now)
	if err != nil {
		return false, fmt.Errorf("initialize instance settings: %w", err)
	}
	var initialized int
	if err := db.Reader().QueryRowContext(ctx, "SELECT initialized FROM instance_settings WHERE singleton = 1").Scan(&initialized); err != nil {
		return false, err
	}
	return initialized == 1, nil
}

func loadInstanceSettings(ctx context.Context, db *database.DB, cfg *config.Runtime) error {
	var trustedJSON string
	if err := db.Reader().QueryRowContext(ctx, `SELECT name, public_url, filesystem_reserve_bytes, trusted_proxy_cidrs
		FROM instance_settings WHERE singleton = 1`).Scan(&cfg.File.InstanceName, &cfg.File.PublicURL, &cfg.File.FilesystemReserveBytes, &trustedJSON); err != nil {
		return fmt.Errorf("load instance settings: %w", err)
	}
	if err := json.Unmarshal([]byte(trustedJSON), &cfg.File.TrustedProxyCIDRs); err != nil {
		return fmt.Errorf("decode trusted proxy settings: %w", err)
	}
	return nil
}

func registerJobs(runner *jobs.Runner, db *database.DB, uploadService *uploads.Service, fileService *files.Service) {
	runner.Register("uploads.reconcile", func(ctx context.Context, _ json.RawMessage) error {
		return uploadService.Reconcile(ctx)
	})
	runner.Register("uploads.expire", func(ctx context.Context, _ json.RawMessage) error {
		_, err := uploadService.Expire(ctx, 500)
		if err != nil {
			return err
		}
		_, err = runner.Enqueue(ctx, "uploads.expire", map[string]any{}, time.Now().Add(time.Hour))
		return err
	})
	runner.Register("public_shares.cleanup", func(ctx context.Context, _ json.RawMessage) error {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		_, err := db.Writer().ExecContext(ctx, `DELETE FROM public_access_sessions WHERE expires_at <= ?`, now)
		if err != nil {
			return err
		}
		_, err = runner.Enqueue(ctx, "public_shares.cleanup", map[string]any{}, time.Now().Add(5*time.Minute))
		return err
	})
	runner.Register("blobs.gc", func(ctx context.Context, _ json.RawMessage) error {
		_, err := uploadService.CollectGarbage(ctx, 500)
		return err
	})
	runner.Register("storage.retention", func(ctx context.Context, _ json.RawMessage) error {
		rows, err := db.Reader().QueryContext(ctx, `SELECT id FROM users WHERE state <> 'deleted' ORDER BY id`)
		if err != nil {
			return err
		}
		var owners []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			owners = append(owners, id)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, ownerID := range owners {
			if _, err := fileService.PruneVersions(ctx, ownerID, 500); err != nil {
				return err
			}
			if _, err := fileService.PurgeExpiredTrash(ctx, ownerID, 100); err != nil {
				return err
			}
			if _, err := fileService.ReconcileQuota(ctx, ownerID); err != nil {
				return err
			}
		}
		_, err = runner.Enqueue(ctx, "storage.retention", map[string]any{}, time.Now().Add(24*time.Hour))
		return err
	})
}

// StartBackground performs crash reconciliation before accepting background
// jobs, then runs the durable worker until the supplied context is cancelled.
func (r *Runtime) StartBackground(parent context.Context) error {
	if err := r.Uploads.Reconcile(parent); err != nil {
		return fmt.Errorf("reconcile uploads: %w", err)
	}
	for _, kind := range []string{"uploads.expire", "public_shares.cleanup", "blobs.gc", "storage.retention"} {
		var pending int
		if err := r.Database.Reader().QueryRowContext(parent, `SELECT COUNT(*) FROM jobs WHERE kind = ? AND state IN ('queued','running')`, kind).Scan(&pending); err != nil {
			return err
		}
		if pending == 0 {
			if _, err := r.Jobs.Enqueue(parent, kind, map[string]any{}, time.Now()); err != nil {
				return err
			}
		}
	}
	ctx, cancel := context.WithCancel(parent)
	r.backgroundStop = cancel
	r.backgroundGroup.Add(1)
	go func() {
		defer r.backgroundGroup.Done()
		if err := r.Jobs.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.Error("background runner stopped", "error", err)
		}
	}()
	r.backgroundGroup.Add(1)
	go func() {
		defer r.backgroundGroup.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			if r.Config.Secrets.WorkOSAPIKey != "" && r.Config.File.WorkOSClientID != "" {
				pollCtx, cancelPoll := context.WithTimeout(ctx, 20*time.Second)
				_, err := r.IdentityEvents.PollOnce(pollCtx, 100)
				cancelPoll()
				if err != nil && !errors.Is(err, context.Canceled) {
					r.logger.Warn("WorkOS event reconciliation failed", "error", err)
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}

func (r *Runtime) Close() error {
	var result error
	r.closeOnce.Do(func() {
		if r.backgroundStop != nil {
			r.backgroundStop()
			r.backgroundGroup.Wait()
		}
		result = errors.Join(r.Database.Close(), r.lock.Close())
	})
	return result
}
