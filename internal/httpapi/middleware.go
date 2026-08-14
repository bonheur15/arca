package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

type contextKey int

const (
	requestIDKey contextKey = iota
	principalKey
)

type Principal struct {
	UserID       string
	Role         string
	State        string
	Scopes       map[string]bool
	SessionID    string
	CSRFToken    string
	CookieAuth   bool
	SupportForID string
}

func (p Principal) Superadmin() bool { return p.Role == "superadmin" }

func (p Principal) HasScope(scope string) bool {
	if p.Superadmin() || p.Scopes["admin:*"] {
		return true
	}
	return p.Scopes[scope]
}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalKey, principal)
}

func GetPrincipal(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalKey).(Principal)
	return principal, ok && principal.UserID != ""
}

func RequestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

type Authenticator interface {
	Authenticate(http.ResponseWriter, *http.Request) (Principal, error)
}

type AuthenticateFunc func(http.ResponseWriter, *http.Request) (Principal, error)

func (f AuthenticateFunc) Authenticate(w http.ResponseWriter, r *http.Request) (Principal, error) {
	return f(w, r)
}

func RequestIDs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if len(id) < 8 || len(id) > 128 || strings.ContainsAny(id, "\r\n\t ") {
			id = randomID(16)
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

func Recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recovered := recover(); recovered != nil {
					logger.Error("request panic", "request_id", RequestID(r.Context()), "panic", recovered, "stack", string(debug.Stack()))
					WriteProblem(w, r, http.StatusInternalServerError, "internal_error", "Internal server error", "The request could not be completed.")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func SecurityHeaders(tlsEnabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			headers := w.Header()
			headers.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; font-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
			headers.Set("Referrer-Policy", "no-referrer")
			headers.Set("X-Content-Type-Options", "nosniff")
			headers.Set("X-Frame-Options", "DENY")
			headers.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
			if tlsEnabled {
				headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

func AccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(recorder, r)
			logger.Info("request", "request_id", RequestID(r.Context()), "method", r.Method,
				"path", r.URL.Path, "status", recorder.status, "bytes", recorder.bytes,
				"duration_ms", time.Since(started).Milliseconds())
		})
	}
}

func RequireAuthentication(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth == nil {
				WriteProblem(w, r, http.StatusUnauthorized, "authentication_required", "Authentication required", "Sign in to continue.")
				return
			}
			principal, err := auth.Authenticate(w, r)
			if err != nil || principal.UserID == "" {
				WriteProblem(w, r, http.StatusUnauthorized, "authentication_required", "Authentication required", "Sign in to continue.")
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
		})
	}
}

func RequireSuperadmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := GetPrincipal(r.Context())
		if !ok || !principal.Superadmin() {
			WriteProblem(w, r, http.StatusForbidden, "admin_required", "Superadmin required", "This operation is restricted to superadmins.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func CSRF(publicURL string) func(http.Handler) http.Handler {
	expected, _ := url.Parse(publicURL)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			principal, ok := GetPrincipal(r.Context())
			if !ok || !principal.CookieAuth {
				next.ServeHTTP(w, r)
				return
			}
			origin := r.Header.Get("Origin")
			parsed, err := url.Parse(origin)
			if err != nil || parsed.Scheme != expected.Scheme || !strings.EqualFold(parsed.Host, expected.Host) {
				WriteProblem(w, r, http.StatusForbidden, "invalid_origin", "Invalid request origin", "The request origin was not accepted.")
				return
			}
			provided := r.Header.Get("X-CSRF-Token")
			if principal.CSRFToken == "" || provided == "" || !constantStringEqual(principal.CSRFToken, provided) {
				WriteProblem(w, r, http.StatusForbidden, "invalid_csrf", "Invalid CSRF token", "Refresh the page and try again.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type Limit struct {
	Capacity int
	Window   time.Duration
}

type Limiter struct {
	mu                 sync.Mutex
	buckets            map[string]*bucket
	publicFailures     []time.Time
	publicCircuitUntil time.Time
	now                func() time.Time
}

type bucket struct {
	count int
	reset time.Time
}

func NewLimiter() *Limiter {
	return &Limiter{buckets: make(map[string]*bucket), now: time.Now}
}

func (l *Limiter) Allow(key string, limit Limit) (bool, time.Duration) {
	if limit.Capacity <= 0 || limit.Window <= 0 {
		return true, 0
	}
	if strings.HasPrefix(key, "public-ip-minute:") {
		key = "public-ip-minute:" + canonicalPublicIP(strings.TrimPrefix(key, "public-ip-minute:"))
	} else if strings.HasPrefix(key, "public-ip-ten:") {
		key = "public-ip-ten:" + canonicalPublicIP(strings.TrimPrefix(key, "public-ip-ten:"))
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if allowed, retry := l.publicExchangeGateLocked(key, now); !allowed {
		return false, retry
	}
	// publicExchangeLimits intentionally checks this instance key after its
	// IP limits. Keeping the breaker here lets the route retain a single,
	// uniform 429 response while failure recording stays in the exchange
	// handler and never needs the submitted code.
	if key == "public-instance" && now.Before(l.publicCircuitUntil) {
		return false, l.publicCircuitUntil.Sub(now)
	}
	allowed, retry := l.allowLocked(key, limit, now)
	if !allowed {
		return false, retry
	}
	// The existing route invokes public-ip-ten:<address> for every exchange
	// that passed the one-minute IP limit. Enforce the adjacent network limit
	// at that same boundary without retaining or inspecting request bodies.
	if strings.HasPrefix(key, "public-ip-ten:") {
		prefix := publicIPPrefix(strings.TrimPrefix(key, "public-ip-ten:"))
		allowed, retry = l.allowLocked("public-prefix-ten:"+prefix, Limit{Capacity: publicPrefixCapacity, Window: 10 * time.Minute}, now)
		if !allowed {
			return false, retry
		}
	}
	l.cleanupLocked(now)
	return true, 0
}

func (l *Limiter) allowLocked(key string, limit Limit, now time.Time) (bool, time.Duration) {
	b := l.buckets[key]
	if b == nil || !now.Before(b.reset) {
		l.buckets[key] = &bucket{count: 1, reset: now.Add(limit.Window)}
		return true, 0
	}
	if b.count >= limit.Capacity {
		return false, b.reset.Sub(now)
	}
	b.count++
	return true, 0
}

func (l *Limiter) cleanupLocked(now time.Time) {
	if len(l.buckets) > 10000 {
		for existingKey, existing := range l.buckets {
			if !now.Before(existing.reset) {
				delete(l.buckets, existingKey)
			}
		}
	}
}

const (
	publicFailureThreshold = 30
	publicFailureWindow    = time.Minute
	publicCircuitDuration  = time.Minute
	publicPrefixCapacity   = 25
	publicInstanceCapacity = 100
)

// publicExchangeGateLocked stops a distributed attacker from allocating a
// fresh bucket for every source address after a broader gate is already full.
// This is especially important for the effectively unbounded address space in
// an IPv6 /64. The route still emits its ordinary generic rate-limit response.
func (l *Limiter) publicExchangeGateLocked(key string, now time.Time) (bool, time.Duration) {
	if !strings.HasPrefix(key, "public-ip-minute:") && !strings.HasPrefix(key, "public-ip-ten:") {
		return true, 0
	}
	if now.Before(l.publicCircuitUntil) {
		return false, l.publicCircuitUntil.Sub(now)
	}
	if instance := l.buckets["public-instance"]; instance != nil && now.Before(instance.reset) && instance.count >= publicInstanceCapacity {
		return false, instance.reset.Sub(now)
	}
	separator := strings.IndexByte(key, ':')
	if separator < 0 || separator == len(key)-1 {
		return true, 0
	}
	prefixKey := "public-prefix-ten:" + publicIPPrefix(key[separator+1:])
	if prefix := l.buckets[prefixKey]; prefix != nil && now.Before(prefix.reset) && prefix.count >= publicPrefixCapacity {
		return false, prefix.reset.Sub(now)
	}
	return true, 0
}

// RecordPublicExchangeFailure tracks only failed five-digit code exchanges.
// No code, body, email, or IP address is accepted or retained by this method.
// Thirty failures within one minute open an instance-wide one-minute breaker;
// the ordinary 100/10-minute instance limit remains in force independently.
func (l *Limiter) RecordPublicExchangeFailure() {
	if l == nil {
		return
	}
	now := l.now()
	cutoff := now.Add(-publicFailureWindow)
	l.mu.Lock()
	defer l.mu.Unlock()
	first := 0
	for first < len(l.publicFailures) && !l.publicFailures[first].After(cutoff) {
		first++
	}
	l.publicFailures = append(l.publicFailures[:0], l.publicFailures[first:]...)
	l.publicFailures = append(l.publicFailures, now)
	if len(l.publicFailures) >= publicFailureThreshold {
		until := now.Add(publicCircuitDuration)
		if until.After(l.publicCircuitUntil) {
			l.publicCircuitUntil = until
		}
	}
}

func publicIPPrefix(raw string) string {
	address, err := netip.ParseAddr(canonicalPublicIP(raw))
	if err != nil {
		return "unknown"
	}
	bits := 64
	if address.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(address, bits).Masked().String()
}

func canonicalPublicIP(raw string) string {
	address, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "unknown"
	}
	return address.Unmap().WithZone("").String()
}

func RateLimit(limiter *Limiter, key func(*http.Request) string, limit Limit) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allowed, retry := limiter.Allow(key(r), limit)
			if !allowed {
				seconds := int(retry.Seconds()) + 1
				w.Header().Set("Retry-After", fmt.Sprint(seconds))
				WriteProblemObject(w, Problem{Type: "https://arca.local/problems/rate_limited", Title: "Too many requests", Status: http.StatusTooManyRequests, Code: "rate_limited", RequestID: RequestID(r.Context()), RetryAfter: seconds})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RemoteIP(r *http.Request, trusted []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	trustedPeer := false
	for _, network := range trusted {
		if peer != nil && network.Contains(peer) {
			trustedPeer = true
			break
		}
	}
	if trustedPeer {
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if len(parts) > 0 {
			candidate := strings.TrimSpace(parts[0])
			if net.ParseIP(candidate) != nil {
				return candidate
			}
		}
	}
	return host
}

func ParseCIDRs(values []string) ([]*net.IPNet, error) {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", value, err)
		}
		result = append(result, network)
	}
	return result, nil
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusRecorder) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(value []byte) (int, error) {
	written, err := w.ResponseWriter.Write(value)
	w.bytes += written
	return written, err
}

func (w *statusRecorder) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func randomID(size int) string {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buffer)
}

func constantStringEqual(first, second string) bool {
	if len(first) != len(second) {
		return false
	}
	var result byte
	for index := range first {
		result |= first[index] ^ second[index]
	}
	return result == 0
}
