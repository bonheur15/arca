package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"arca/internal/accounts"
	"arca/internal/app"
	"arca/internal/auth"
	"arca/internal/files"
	"arca/internal/shares"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

type Server struct {
	runtime     *app.Runtime
	logger      *slog.Logger
	router      chi.Router
	trusted     []*net.IPNet
	limiter     *Limiter
	idempotency *IdempotencyStore
	events      *Hub
	web         fs.FS
	openapiYAML []byte
}

func NewServer(runtime *app.Runtime, webAssets, apiAssets fs.FS, logger *slog.Logger) (*Server, error) {
	if runtime == nil || runtime.Database == nil {
		return nil, errors.New("httpapi: runtime is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	trusted, err := ParseCIDRs(runtime.Config.File.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	if _, err := ParseOrigins(runtime.Config.File.AllowedCORSOrigins); err != nil {
		return nil, err
	}
	webRoot, err := fs.Sub(webAssets, "dist")
	if err != nil {
		return nil, fmt.Errorf("open embedded web distribution: %w", err)
	}
	contract, err := fs.ReadFile(apiAssets, "openapi.yaml")
	if err != nil {
		return nil, fmt.Errorf("read embedded OpenAPI contract: %w", err)
	}
	server := &Server{
		runtime: runtime, logger: logger, trusted: trusted, limiter: NewLimiter(),
		idempotency: NewIdempotencyStore(runtime.Database.Writer()), events: NewHub(),
		web: webRoot, openapiYAML: contract,
	}
	server.router = server.routes()
	return server, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.router.ServeHTTP(w, r) }

func (s *Server) routes() chi.Router {
	router := chi.NewRouter()
	router.Use(RequestIDs)
	cors, _ := CORS(s.runtime.Config.File.AllowedCORSOrigins)
	router.Use(cors)
	router.Use(Recoverer(s.logger))
	router.Use(SecurityHeaders(s.runtime.Config.TLSCert != ""))
	router.Use(AccessLog(s.logger))

	router.Get("/health/live", s.live)
	router.Get("/health/ready", s.ready)
	router.Get("/api/openapi.yaml", s.openapiYAMLHandler)
	router.Get("/api/openapi.json", s.openapiJSONHandler)
	router.Get("/api/docs", s.docs)

	router.Route("/api/v1", func(api chi.Router) {
		api.Get("/bootstrap/status", s.bootstrapStatus)
		api.With(s.rate("setup", Limit{Capacity: 12, Window: time.Minute})).Post("/bootstrap/validate", s.bootstrapValidate)
		api.With(s.rate("setup", Limit{Capacity: 8, Window: time.Minute})).Post("/bootstrap/start", s.bootstrapStart)
		api.With(s.rate("setup", Limit{Capacity: 12, Window: 10 * time.Minute})).Post("/bootstrap/verify", s.bootstrapVerify)
		api.With(s.rate("magic-start", Limit{Capacity: 5, Window: time.Minute})).Post("/auth/magic/start", s.magicStart)
		api.With(s.rate("magic-verify", Limit{Capacity: 10, Window: 10 * time.Minute})).Post("/auth/magic/verify", s.magicVerify)
		api.With(s.rate("access-request", Limit{Capacity: 5, Window: 10 * time.Minute})).Post("/access-requests", s.requestAccess)
		api.Get("/access-requests/status", s.accessRequestStatus)
		api.With(s.publicExchangeLimits).Post("/public/exchange", s.publicExchange)
		api.Get("/public/bundle", s.publicBundle)
		api.Get("/public/files/{nodeID}/content", s.publicContent)
		api.Get("/session", s.session)

		api.Group(func(private chi.Router) {
			private.Use(RequireAuthentication(AuthenticateFunc(s.authenticate)))
			private.Use(s.csrf)
			private.Post("/auth/logout", s.logout)
			private.Get("/sessions", s.sessions)
			private.Delete("/sessions/{sessionID}", s.revokeSession)
			private.Get("/me", s.me)
			private.Patch("/me", s.updateMe)
			private.Put("/me/preferences", s.updatePreferences)
			private.Get("/users/lookup", s.lookupUser)
			private.Get("/support-access", s.activeSupportAccess)
			private.Delete("/support-access/{accessID}", s.revokeSupportAccess)

			private.Get("/nodes", s.listNodes)
			private.Get("/nodes/{nodeID}", s.getNode)
			private.With(s.idempotent).Post("/nodes/bulk", s.bulkNodes)
			private.Post("/nodes/archive", s.archiveNodes)
			private.Post("/folders", s.createFolder)
			private.Patch("/nodes/{nodeID}", s.renameNode)
			private.With(s.idempotent).Post("/nodes/{nodeID}/move", s.moveNode)
			private.With(s.idempotent).Post("/nodes/{nodeID}/copy", s.copyNode)
			private.With(s.idempotent).Post("/nodes/{nodeID}/save-copy", s.saveNodeCopy)
			private.With(s.idempotent).Post("/nodes/{nodeID}/trash", s.trashNode)
			private.With(s.idempotent).Post("/nodes/{nodeID}/restore", s.restoreNode)
			private.With(s.idempotent).Post("/nodes/{nodeID}/purge", s.purgeNode)
			private.Get("/trash", s.trash)
			private.Get("/recent", s.recent)
			private.Get("/favorites", s.favorites)
			private.Put("/favorites/{nodeID}", s.favorite)
			private.Delete("/favorites/{nodeID}", s.unfavorite)
			private.Get("/search", s.search)
			private.Get("/files/{nodeID}/versions", s.versions)
			private.Post("/files/{nodeID}/versions/{versionID}/restore", s.restoreVersion)
			private.Get("/files/{nodeID}/content", s.content)

			private.With(s.tusHeaders, s.idempotent).Post("/uploads", s.createUpload)
			private.With(s.tusHeaders).Head("/uploads/{uploadID}", s.headUpload)
			private.With(s.tusHeaders).Patch("/uploads/{uploadID}", s.patchUpload)
			private.With(s.tusHeaders).Delete("/uploads/{uploadID}", s.cancelUpload)

			private.Get("/shared", s.shared)
			private.Get("/shares", s.listShares)
			private.With(s.idempotent).Post("/shares", s.createShare)
			private.Delete("/shares/{shareID}", s.revokeShare)
			private.Get("/public-shares", s.listPublicShares)
			private.With(s.idempotent).Post("/public-shares", s.createPublicShare)
			private.Delete("/public-shares/{shareID}", s.revokePublicShare)

			private.Get("/tokens", s.listTokens)
			private.Post("/tokens", s.createToken)
			private.Delete("/tokens/{tokenID}", s.revokeToken)
			private.Get("/notifications", s.notifications)
			private.Get("/events", s.events.ServeHTTP)

			private.Route("/admin", func(admin chi.Router) {
				admin.Use(RequireSuperadmin)
				admin.Get("/users", s.adminUsers)
				admin.Post("/users", s.adminCreateUser)
				admin.Patch("/users/{userID}", s.adminUpdateUser)
				admin.Get("/requests", s.adminRequests)
				admin.Post("/requests/{requestID}", s.adminDecideRequest)
				admin.Get("/policies/{userID}", s.adminPolicy)
				admin.Put("/policies/{userID}", s.adminSavePolicy)
				admin.Get("/storage", s.adminStorage)
				admin.Get("/jobs", s.adminJobs)
				admin.Post("/jobs/{jobID}/retry", s.adminRetryJob)
				admin.Get("/audit", s.adminAudit)
				admin.Get("/settings", s.adminSettings)
				admin.Put("/settings", s.adminSaveSettings)
				admin.Post("/support-access", s.adminSupportAccess)
			})
		})
	})
	router.NotFound(s.webHandler)
	return router
}

func (s *Server) live(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]any{"status": "live", "version": s.runtime.Version})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	status, err := s.runtime.Bootstrap.Status(ctx)
	if err != nil || s.runtime.Database.Check(ctx) != nil {
		WriteProblem(w, r, http.StatusServiceUnavailable, "not_ready", "Instance not ready", "Database or storage checks failed.")
		return
	}
	free, err := s.runtime.Storage.FreeBytes()
	if err != nil || free < s.runtime.Config.File.FilesystemReserveBytes {
		WriteProblem(w, r, http.StatusServiceUnavailable, "disk_reserve_exceeded", "Instance not ready", "The filesystem reserve is exhausted.")
		return
	}
	if !status.Initialized {
		WriteProblem(w, r, http.StatusServiceUnavailable, "setup_required", "Setup required", "Complete first-run setup before serving users.")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "ready", "sqlite_version": s.runtime.SQLiteVersion})
}

func (s *Server) openapiYAMLHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(s.openapiYAML)
}

func (s *Server) openapiJSONHandler(w http.ResponseWriter, r *http.Request) {
	var value any
	if err := yaml.Unmarshal(s.openapiYAML, &value); err != nil {
		s.handleError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, value)
}

func (s *Server) docs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Arca API</title><style>body{font:16px/1.5 system-ui;max-width:760px;margin:10vh auto;padding:24px;color:#18201d;background:#f6f5f2}a{color:#166856}code{background:#e9ece8;padding:.2rem .4rem;border-radius:4px}</style></head><body><h1>Arca API v1</h1><p>The versioned REST API is available beneath <code>/api/v1</code>. Errors use RFC 9457 problem details. Browser clients use sealed cookies; external clients use <code>arca_pat_</code> bearer tokens.</p><p><a href="/api/openapi.yaml">OpenAPI YAML</a> · <a href="/api/openapi.json">OpenAPI JSON</a></p></body></html>`)
}

func (s *Server) webHandler(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/health/") {
		WriteProblem(w, r, http.StatusNotFound, "not_found", "Not found", "The requested endpoint does not exist.")
		return
	}
	requested := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if requested == "." || requested == "" {
		requested = "index.html"
	}
	if info, err := fs.Stat(s.web, requested); err == nil && info.Mode().IsRegular() {
		if strings.Contains(path.Base(requested), ".") && requested != "index.html" {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeFileFS(w, r, s.web, requested)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFileFS(w, r, s.web, "index.html")
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (Principal, error) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if authorization != "" {
		parts := strings.SplitN(authorization, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !strings.HasPrefix(parts[1], "arca_pat_") {
			return Principal{}, auth.ErrInvalidToken
		}
		token, err := s.runtime.Tokens.Authenticate(r.Context(), parts[1])
		if err != nil {
			return Principal{}, err
		}
		scopes := make(map[string]bool, len(token.Scopes))
		for scope := range token.Scopes {
			scopes[string(scope)] = true
		}
		return Principal{UserID: token.User.ID, Role: string(token.User.Role), State: string(token.User.State), Scopes: scopes}, nil
	}
	policy := s.cookiePolicy()
	sealed, err := auth.ReadCookie(r, policy.SessionName())
	if err != nil {
		return Principal{}, err
	}
	principal, err := s.runtime.Authentication.Authenticate(r.Context(), sealed)
	if err != nil {
		return Principal{}, err
	}
	if principal.RotatedSealedSession != "" {
		policy.SetSession(w, principal.RotatedSealedSession, time.Now().Add(30*24*time.Hour))
	}
	csrfValue := ""
	if cookie, cookieErr := r.Cookie(policy.CSRFName()); cookieErr == nil {
		csrfValue = cookie.Value
	}
	return Principal{UserID: principal.User.ID, Role: string(principal.User.Role), State: string(principal.User.State), SessionID: principal.SessionID, CSRFToken: csrfValue, CookieAuth: true}, nil
}

func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		principal, _ := GetPrincipal(r.Context())
		if !principal.CookieAuth {
			next.ServeHTTP(w, r)
			return
		}
		expected, err := url.Parse(s.runtime.Config.File.PublicURL)
		origin, originErr := url.Parse(r.Header.Get("Origin"))
		if err != nil || originErr != nil || expected.Scheme == "" || expected.Host == "" || origin.Scheme != expected.Scheme || !strings.EqualFold(origin.Host, expected.Host) {
			WriteProblem(w, r, http.StatusForbidden, "invalid_origin", "Invalid request origin", "The request origin was not accepted.")
			return
		}
		if err := auth.ValidateCSRFToken(s.runtime.CSRFSecret, principal.SessionID, principal.CSRFToken, r.Header.Get("X-CSRF-Token")); err != nil {
			WriteProblem(w, r, http.StatusForbidden, "invalid_csrf", "Invalid CSRF token", "Refresh the page and try again.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cookiePolicy() auth.CookiePolicy {
	secure := s.runtime.Config.TLSCert != ""
	if parsed, err := url.Parse(s.runtime.Config.File.PublicURL); err == nil && parsed.Scheme == "https" {
		secure = true
	}
	return auth.DefaultCookiePolicy(secure)
}

func (s *Server) rate(namespace string, limit Limit) func(http.Handler) http.Handler {
	return RateLimit(s.limiter, func(r *http.Request) string { return namespace + ":" + s.remoteIP(r) }, limit)
}

func (s *Server) publicExchangeLimits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.remoteIP(r)
		for _, item := range []struct {
			key   string
			limit Limit
		}{
			{"public-ip-minute:" + ip, Limit{Capacity: 5, Window: time.Minute}},
			{"public-ip-ten:" + ip, Limit{Capacity: 10, Window: 10 * time.Minute}},
			{"public-instance", Limit{Capacity: 100, Window: 10 * time.Minute}},
		} {
			allowed, retry := s.limiter.Allow(item.key, item.limit)
			if !allowed {
				seconds := int(retry.Seconds()) + 1
				w.Header().Set("Retry-After", strconv.Itoa(seconds))
				WriteProblemObject(w, Problem{Status: http.StatusTooManyRequests, Code: "rate_limited", Title: "Too many requests", RequestID: RequestID(r.Context()), RetryAfter: seconds})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) remoteIP(r *http.Request) string { return RemoteIP(r, s.trusted) }

type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *bufferedResponse) Header() http.Header { return r.header }
func (r *bufferedResponse) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}
func (r *bufferedResponse) Write(body []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(body)
}

func (s *Server) idempotent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if len(key) < 8 || len(key) > 200 {
			WriteProblem(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency key required", "Provide a stable Idempotency-Key for this operation.")
			return
		}
		principal, ok := GetPrincipal(r.Context())
		if !ok {
			WriteProblem(w, r, http.StatusUnauthorized, "authentication_required", "Authentication required", "Sign in to continue.")
			return
		}
		digest, body, err := RequestDigest(r, 1<<20)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		stored, err := s.idempotency.Lookup(r.Context(), principal.UserID, key, digest)
		if err != nil {
			s.handleError(w, r, err)
			return
		}
		if stored != nil {
			for name, values := range stored.Headers {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}
			w.WriteHeader(stored.Status)
			_, _ = w.Write(stored.Body)
			return
		}
		buffer := &bufferedResponse{header: make(http.Header)}
		next.ServeHTTP(buffer, r)
		if buffer.status == 0 {
			buffer.status = http.StatusOK
		}
		if buffer.status < 500 {
			if err := s.idempotency.Save(r.Context(), principal.UserID, key, digest, StoredResponse{Status: buffer.status, Headers: buffer.header, Body: buffer.body.Bytes()}); err != nil {
				s.handleError(w, r, err)
				return
			}
		}
		for name, values := range buffer.header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(buffer.status)
		_, _ = w.Write(buffer.body.Bytes())
	})
}

func (s *Server) tusHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Tus-Resumable", "1.0.0")
		w.Header().Set("Tus-Version", "1.0.0")
		w.Header().Set("Tus-Extension", "creation,expiration,termination,checksum")
		w.Header().Set("Tus-Max-Size", strconv.FormatInt(1<<50, 10))
		if r.Method != http.MethodOptions && r.Header.Get("Tus-Resumable") != "1.0.0" {
			WriteProblem(w, r, http.StatusPreconditionFailed, "tus_version_required", "Tus version required", "Set Tus-Resumable: 1.0.0.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	var domain *files.Error
	if errors.As(err, &domain) {
		status := map[files.ErrorCode]int{
			files.CodeInvalid: http.StatusBadRequest, files.CodeInvalidName: http.StatusBadRequest,
			files.CodeNotFound: http.StatusNotFound, files.CodeForbidden: http.StatusForbidden,
			files.CodeConflict: http.StatusConflict, files.CodeRevisionMismatch: http.StatusPreconditionFailed,
			files.CodePreconditionRequired: http.StatusPreconditionRequired, files.CodeCycle: http.StatusConflict,
			files.CodeItemLimit: http.StatusConflict, files.CodeQuota: http.StatusInsufficientStorage,
			files.CodeDiskFull: http.StatusInsufficientStorage, files.CodeUploadLimit: http.StatusTooManyRequests,
			files.CodeOffsetMismatch: http.StatusConflict, files.CodeChecksumMismatch: http.StatusBadRequest,
			files.CodeFileTypeBlocked: http.StatusUnsupportedMediaType,
			files.CodeExpired:         http.StatusGone, files.CodeInvalidState: http.StatusConflict,
		}[domain.Code]
		if status == 0 {
			status = http.StatusBadRequest
		}
		WriteProblem(w, r, status, string(domain.Code), http.StatusText(status), domain.Detail)
		return
	}
	switch {
	case errors.Is(err, accounts.ErrNotFound), errors.Is(err, shares.ErrNotFound):
		WriteProblem(w, r, http.StatusNotFound, "not_found", "Not found", "The requested resource was not found.")
	case errors.Is(err, accounts.ErrForbidden), errors.Is(err, auth.ErrForbidden), errors.Is(err, shares.ErrForbidden):
		WriteProblem(w, r, http.StatusForbidden, "forbidden", "Forbidden", "You do not have permission to perform this operation.")
	case errors.Is(err, accounts.ErrConflict), errors.Is(err, accounts.ErrLastSuperadmin), errors.Is(err, accounts.ErrInvalidTransition), errors.Is(err, accounts.ErrRequestDecided):
		WriteProblem(w, r, http.StatusConflict, "conflict", "Conflict", err.Error())
	case errors.Is(err, accounts.ErrInvalidInput), errors.Is(err, shares.ErrInvalid):
		WriteProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", err.Error())
	case errors.Is(err, auth.ErrRateLimited):
		retryAfter := 60
		var limited *auth.RateLimitError
		if errors.As(err, &limited) && limited.RetryAfter > 0 {
			retryAfter = int(limited.RetryAfter.Seconds()) + 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		WriteProblemObject(w, Problem{Status: http.StatusTooManyRequests, Code: "rate_limited", Title: "Too many requests", RequestID: RequestID(r.Context()), RetryAfter: retryAfter})
	case errors.Is(err, auth.ErrSessionUnavailable):
		WriteProblem(w, r, http.StatusServiceUnavailable, "authentication_unavailable", "Authentication temporarily unavailable", "Your session was preserved. Try again shortly.")
	case errors.Is(err, accounts.ErrAuditFailed):
		WriteProblem(w, r, http.StatusInternalServerError, "audit_recording_failed", "Operation committed with an audit error", "The change was saved, but its audit event could not be recorded. Do not retry blindly.")
	case errors.Is(err, accounts.ErrInvalidStatusToken), errors.Is(err, auth.ErrInvalidCredentials), errors.Is(err, auth.ErrUnauthenticated), errors.Is(err, auth.ErrInvalidToken):
		WriteProblem(w, r, http.StatusUnauthorized, "invalid_credentials", "Invalid credentials", "The supplied credentials are invalid or expired.")
	case errors.Is(err, shares.ErrPublicUnavailable):
		WriteProblem(w, r, http.StatusNotFound, "public_share_unavailable", "Share unavailable", "The code is invalid or the share is no longer available.")
	case errors.Is(err, sql.ErrNoRows):
		WriteProblem(w, r, http.StatusNotFound, "not_found", "Not found", "The requested resource was not found.")
	default:
		HandleError(s.logger, w, r, err)
	}
}

func decodeBody(w http.ResponseWriter, r *http.Request, value any) error {
	return DecodeJSON(w, r, value)
}

func revisionFromRequest(r *http.Request) (int64, error) {
	value := strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), `"`)
	if value == "" {
		return 0, files.NewError(files.CodePreconditionRequired, "parse revision", "", "If-Match is required")
	}
	revision, err := strconv.ParseInt(value, 10, 64)
	if err != nil || revision <= 0 {
		return 0, files.NewError(files.CodePreconditionRequired, "parse revision", "", "If-Match must contain a positive revision")
	}
	return revision, nil
}

func principal(r *http.Request) Principal {
	value, _ := GetPrincipal(r.Context())
	return value
}

func mutation(r *http.Request, remoteIP string) accounts.MutationContext {
	return accounts.MutationContext{ActorID: principal(r).UserID, IPAddress: remoteIP, UserAgent: r.UserAgent(), RequestID: RequestID(r.Context())}
}

func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func parseTimePointer(value string) (*time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, err
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func cloneHeader(destination, source http.Header) {
	for name, values := range source {
		destination[name] = append([]string(nil), values...)
	}
}

var _ = json.Valid
