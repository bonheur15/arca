package httpapi

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ParseOrigins validates exact CORS origins. Wildcards and URL paths are
// intentionally unsupported so an operator cannot accidentally authorize a
// broader credential boundary than intended.
func ParseOrigins(values []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return nil, fmt.Errorf("invalid CORS origin %q", value)
		}
		if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
			return nil, fmt.Errorf("CORS origin %q must use HTTPS unless it is loopback", value)
		}
		origin := strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
		result[origin] = struct{}{}
	}
	return result, nil
}

func CORS(values []string) (func(http.Handler) http.Handler, error) {
	allowed, err := ParseOrigins(values)
	if err != nil {
		return nil, err
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			parsed, parseErr := url.Parse(origin)
			canonical := ""
			if parseErr == nil && parsed.Scheme != "" && parsed.Host != "" {
				canonical = strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
			}
			_, ok := allowed[canonical]
			if !ok {
				if r.Method == http.MethodOptions {
					WriteProblem(w, r, http.StatusForbidden, "cors_origin_denied", "Origin denied", "This origin is not allowed to use the Arca API.")
					return
				}
				// Omitting Access-Control-Allow-Origin makes the response
				// unreadable to an untrusted browser origin. Cookie mutations
				// are independently rejected by Origin and CSRF validation.
				next.ServeHTTP(w, r)
				return
			}
			header := w.Header()
			header.Set("Access-Control-Allow-Origin", origin)
			header.Add("Vary", "Origin")
			header.Set("Access-Control-Expose-Headers", "ETag, Location, Upload-Offset, Upload-Length, Upload-Expires, Tus-Resumable, X-Request-ID")
			if r.Method == http.MethodOptions {
				header.Set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS")
				header.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-Match, Idempotency-Key, Upload-Length, Upload-Metadata, Upload-Offset, Upload-Checksum, Tus-Resumable")
				header.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

func sortedOrigins(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".localhost")
}
