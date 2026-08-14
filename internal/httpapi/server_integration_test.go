package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"arca/api"
	"arca/internal/app"
	"arca/internal/config"
	"arca/internal/httpapi"
	webassets "arca/web"
)

func TestUninitializedServerHealthContractAndEmbeddedAssets(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cfg, err := config.Load(config.Overrides{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cfg.File.FilesystemReserveBytes = 0
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtime, err := app.Open(ctx, cfg, "integration-test", logger)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	server, err := httpapi.NewServer(runtime, webassets.Dist, api.Files, logger)
	if err != nil {
		t.Fatal(err)
	}

	assertRequest := func(method, target, body string, wantStatus int) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(method, target, strings.NewReader(body))
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != wantStatus {
			t.Fatalf("%s %s status = %d, want %d: %s", method, target, response.Code, wantStatus, response.Body.String())
		}
		if response.Header().Get("X-Request-ID") == "" {
			t.Fatalf("%s %s did not return a request ID", method, target)
		}
		if response.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s %s did not return security headers", method, target)
		}
		return response
	}

	live := assertRequest(http.MethodGet, "/health/live", "", http.StatusOK)
	if !strings.Contains(live.Body.String(), `"version":"integration-test"`) {
		t.Fatalf("unexpected liveness response: %s", live.Body.String())
	}
	ready := assertRequest(http.MethodGet, "/health/ready", "", http.StatusServiceUnavailable)
	if !strings.Contains(ready.Body.String(), `"code":"setup_required"`) {
		t.Fatalf("unexpected readiness response: %s", ready.Body.String())
	}
	setup := assertRequest(http.MethodGet, "/setup", "", http.StatusOK)
	if !strings.Contains(strings.ToLower(setup.Body.String()), "<!doctype html>") || !strings.Contains(setup.Body.String(), `<div id="root"></div>`) {
		t.Fatalf("embedded SPA was not served: %s", setup.Body.String())
	}
	contract := assertRequest(http.MethodGet, "/api/openapi.json", "", http.StatusOK)
	var document struct {
		OpenAPI string                     `json:"openapi"`
		Paths   map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(contract.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.OpenAPI != "3.0.3" || document.Paths["/uploads"] == nil || document.Paths["/public/exchange"] == nil {
		t.Fatalf("unexpected embedded OpenAPI document: version=%q paths=%d", document.OpenAPI, len(document.Paths))
	}
	publicFailure := assertRequest(http.MethodPost, "/api/v1/public/exchange", `{"code":"00000"}`, http.StatusNotFound)
	if publicFailure.Header().Get("Cache-Control") != "no-store" || !strings.Contains(publicFailure.Body.String(), `"code":"public_share_unavailable"`) {
		t.Fatalf("public exchange failure leaked a distinct response: %s", publicFailure.Body.String())
	}
}
