package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSAllowsOnlyExactConfiguredOrigins(t *testing.T) {
	t.Parallel()
	middleware, err := CORS([]string{"https://client.example", "http://localhost:5173"})
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	allowed := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodOptions, "/api/v1/nodes", nil)
	request.Header.Set("Origin", "https://client.example")
	handler.ServeHTTP(allowed, request)
	if allowed.Code != http.StatusNoContent || allowed.Header().Get("Access-Control-Allow-Origin") != "https://client.example" {
		t.Fatalf("configured origin was not allowed: status=%d headers=%v", allowed.Code, allowed.Header())
	}
	if allowed.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("cross-origin cookie credentials must remain disabled")
	}

	denied := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodOptions, "/api/v1/nodes", nil)
	request.Header.Set("Origin", "https://evil.example")
	handler.ServeHTTP(denied, request)
	if denied.Code != http.StatusForbidden || denied.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unconfigured origin was not denied: status=%d headers=%v", denied.Code, denied.Header())
	}
}

func TestParseOriginsRejectsWildcardsPathsAndInsecureRemoteOrigins(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"*", "https://example.com/path", "http://example.com", "https://user@example.com"} {
		if _, err := ParseOrigins([]string{value}); err == nil {
			t.Fatalf("invalid origin %q unexpectedly accepted", value)
		}
	}
}
