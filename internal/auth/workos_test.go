package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"arca/internal/accounts"

	workos "github.com/workos/workos-go/v10"
)

func TestWorkOSProviderMagicAuthContract(t *testing.T) {
	var magicBody, verifyBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/user_management/magic_auth":
			if request.Method != http.MethodPost {
				t.Fatalf("magic method = %s", request.Method)
			}
			if err := json.NewDecoder(request.Body).Decode(&magicBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "magic_123", "user_id": "user_123", "email": "alice@example.com",
				"expires_at": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano),
				"created_at": time.Now().UTC().Format(time.RFC3339Nano),
				"updated_at": time.Now().UTC().Format(time.RFC3339Nano),
				"code":       "987654", "radar_auth_attempt_id": "radar_123",
			})
		case "/user_management/authenticate":
			if err := json.NewDecoder(request.Body).Decode(&verifyBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user":          map[string]any{"id": "user_123", "email": "alice@example.com"},
				"access_token":  fakeJWT("session_123", time.Now().Add(time.Hour)),
				"refresh_token": "refresh_123",
			})
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	provider, err := NewWorkOSProvider("sk_test", "client_test", workos.WithBaseURL(server.URL), workos.WithMaxRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := provider.SendMagic(context.Background(), MagicStartRequest{
		Email: "alice@example.com", IPAddress: "192.0.2.10", UserAgent: "Arca test",
		RadarAuthAttemptID: "incoming_radar", SignalsID: "signals_123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if challenge.ID != "magic_123" || challenge.UserID != "user_123" || challenge.RadarAuthAttemptID != "radar_123" {
		t.Fatalf("challenge = %#v", challenge)
	}
	encodedChallenge, _ := json.Marshal(challenge)
	if strings.Contains(string(encodedChallenge), "987654") {
		t.Fatal("Magic Auth code leaked through domain challenge")
	}
	if magicBody["email"] != "alice@example.com" || magicBody["ip_address"] != "192.0.2.10" || magicBody["signals_id"] != "signals_123" {
		t.Fatalf("magic body = %#v", magicBody)
	}
	authentication, err := provider.VerifyMagic(context.Background(), MagicVerifyRequest{
		Email: "alice@example.com", Code: "123456", IPAddress: "192.0.2.10",
		UserAgent: "Arca test", RadarAuthAttemptID: challenge.RadarAuthAttemptID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if authentication.WorkOSUserID != "user_123" || authentication.RefreshToken != "refresh_123" {
		t.Fatalf("authentication = %#v", authentication)
	}
	if verifyBody["grant_type"] != "urn:workos:oauth:grant-type:magic-auth:code" || verifyBody["code"] != "123456" || verifyBody["radar_auth_attempt_id"] != "radar_123" {
		t.Fatalf("verify body = %#v", verifyBody)
	}
	sealed, err := provider.SealSession(authentication, "cookie-password")
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := provider.InspectSession(sealed, "cookie-password")
	if err != nil || !inspection.Authenticated || inspection.SessionID != "session_123" || inspection.WorkOSUserID != "user_123" {
		t.Fatalf("inspection = %#v, err = %v", inspection, err)
	}
}

func TestWorkOSProviderReconcileUsesExternalID(t *testing.T) {
	var createCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(request.URL.Path, "/user_management/users/external_id/") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "user_123", "email": "alice@example.com", "external_id": "arca_123",
			})
			return
		}
		if request.URL.Path == "/user_management/users" {
			createCalls++
		}
		http.NotFound(w, request)
	}))
	t.Cleanup(server.Close)
	provider, err := NewWorkOSProvider("sk_test", "client_test", workos.WithBaseURL(server.URL), workos.WithMaxRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.ReconcileUser(context.Background(), accounts.IdentityRequest{
		ArcaUserID: "arca_123", Email: "ALICE@example.com", DisplayName: "Alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if identity.ID != "user_123" || createCalls != 0 {
		t.Fatalf("identity = %#v, create calls = %d", identity, createCalls)
	}
}

func TestWorkOSProviderReconcileAdoptsUnclaimedEmail(t *testing.T) {
	var updateBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(request.URL.Path, "/user_management/users/external_id/"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"not_found","message":"missing"}`))
		case request.URL.Path == "/user_management/users" && request.Method == http.MethodPost:
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"code":"user_exists","message":"already exists"}`))
		case request.URL.Path == "/user_management/users" && request.Method == http.MethodGet:
			if request.URL.Query().Get("email") != "alice@example.com" {
				t.Fatalf("email filter = %q", request.URL.Query().Get("email"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data":          []map[string]any{{"id": "user_existing", "email": "alice@example.com", "external_id": nil}},
				"list_metadata": map[string]any{"after": nil, "before": nil},
			})
		case request.URL.Path == "/user_management/users/user_existing" && request.Method == http.MethodPut:
			if err := json.NewDecoder(request.Body).Decode(&updateBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": "user_existing", "email": "alice@example.com", "external_id": "arca_123",
			})
		default:
			http.NotFound(w, request)
		}
	}))
	t.Cleanup(server.Close)
	provider, _ := NewWorkOSProvider("sk_test", "client_test", workos.WithBaseURL(server.URL), workos.WithMaxRetries(0))
	identity, err := provider.ReconcileUser(context.Background(), accounts.IdentityRequest{ArcaUserID: "arca_123", Email: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if identity.ID != "user_existing" || updateBody["external_id"] != "arca_123" {
		t.Fatalf("identity = %#v, update body = %#v", identity, updateBody)
	}
}

func TestWorkOSProviderListsBoundedEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/events" {
			http.NotFound(w, request)
			return
		}
		if request.URL.Query().Get("order") != "asc" || request.URL.Query().Get("after") != "evt_before" {
			t.Fatalf("event query = %q", request.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"id": "evt_1", "event": EventUserUpdated, "data": map[string]any{"id": "user_1", "email": "new@example.com"}, "created_at": time.Now().Format(time.RFC3339)},
				{"id": "evt_2", "event": EventSessionRevoked, "data": map[string]any{"id": "session_1", "user_id": "user_1", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)}, "created_at": time.Now().Format(time.RFC3339)},
			},
			"list_metadata": map[string]any{"after": nil, "before": nil},
		})
	}))
	t.Cleanup(server.Close)
	provider, _ := NewWorkOSProvider("sk_test", "client_test", workos.WithBaseURL(server.URL), workos.WithMaxRetries(0))
	events, cursor, err := provider.ListIdentityEvents(context.Background(), "evt_before", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || cursor != "evt_2" || events[0].Email != "new@example.com" || events[1].SessionID != "session_1" {
		t.Fatalf("events = %#v, cursor = %q", events, cursor)
	}
}
