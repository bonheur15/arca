package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"arca/internal/app"
	"arca/internal/database"
	"arca/internal/shares"
	"arca/migrations"
)

func TestPublicExchangeLimitsPerIP(t *testing.T) {
	clock := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	server, handler, reached := newPublicLimitHarness(&clock, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for attempt := 1; attempt <= 5; attempt++ {
		response := performPublicExchange(handler, "203.0.113.9")
		if response.Code != http.StatusNoContent {
			t.Fatalf("attempt %d status = %d", attempt, response.Code)
		}
	}
	response := performPublicExchange(handler, "203.0.113.9")
	assertRateLimited(t, response)
	if *reached != 5 {
		t.Fatalf("handler reached %d times, want 5", *reached)
	}

	// Reset the harness to isolate the ten-minute per-IP window. Two groups of
	// five fit into separate minute windows but the eleventh request must fail.
	server.limiter = NewLimiter()
	server.limiter.now = func() time.Time { return clock }
	handler = server.publicExchangeLimits(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		(*reached)++
		w.WriteHeader(http.StatusNoContent)
	}))
	*reached = 0
	for group := 0; group < 2; group++ {
		for attempt := 0; attempt < 5; attempt++ {
			if response := performPublicExchange(handler, "203.0.113.10"); response.Code != http.StatusNoContent {
				t.Fatalf("group %d attempt %d status = %d", group, attempt, response.Code)
			}
		}
		clock = clock.Add(time.Minute)
	}
	response = performPublicExchange(handler, "203.0.113.10")
	assertRateLimited(t, response)
	if *reached != 10 {
		t.Fatalf("handler reached %d times, want 10", *reached)
	}
}

func TestPublicExchangeLimitsCanonicalizeIPAndEnforcePrefixes(t *testing.T) {
	clock := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

	t.Run("alternate IPv6 spellings share an IP bucket", func(t *testing.T) {
		_, handler, reached := newPublicLimitHarness(&clock, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		spellings := []string{
			"2001:db8::1",
			"2001:0db8:0:0:0:0:0:1",
			"2001:db8:0::1",
			"2001:db8::0:1",
			"2001:0db8::0001",
		}
		for _, address := range spellings {
			if response := performPublicExchange(handler, address); response.Code != http.StatusNoContent {
				t.Fatalf("address %q status = %d", address, response.Code)
			}
		}
		assertRateLimited(t, performPublicExchange(handler, "2001:db8::1"))
		if *reached != 5 {
			t.Fatalf("handler reached %d times, want 5", *reached)
		}
	})

	for _, test := range []struct {
		name string
		ip   func(int) string
	}{
		{name: "IPv4 /24", ip: func(index int) string { return fmt.Sprintf("203.0.113.%d", index+1) }},
		{name: "IPv6 /64", ip: func(index int) string { return fmt.Sprintf("2001:db8:1:2::%x", index+1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, handler, reached := newPublicLimitHarness(&clock, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			for index := 0; index < 25; index++ {
				response := performPublicExchange(handler, test.ip(index))
				if response.Code != http.StatusNoContent {
					t.Fatalf("attempt %d status = %d", index+1, response.Code)
				}
			}
			assertRateLimited(t, performPublicExchange(handler, test.ip(25)))
			if *reached != 25 {
				t.Fatalf("handler reached %d times, want 25", *reached)
			}
		})
	}

	if got := publicIPPrefix("::ffff:203.0.113.55"); got != "203.0.113.0/24" {
		t.Fatalf("mapped IPv4 prefix = %q", got)
	}
	if got := publicIPPrefix("2001:db8:1:2::abcd"); got != "2001:db8:1:2::/64" {
		t.Fatalf("IPv6 prefix = %q", got)
	}
}

func TestPublicExchangeLimitsInstanceWindow(t *testing.T) {
	clock := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	_, handler, reached := newPublicLimitHarness(&clock, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for index := 0; index < 100; index++ {
		address := fmt.Sprintf("10.%d.0.1", index)
		response := performPublicExchange(handler, address)
		if response.Code != http.StatusNoContent {
			t.Fatalf("attempt %d status = %d", index+1, response.Code)
		}
	}
	assertRateLimited(t, performPublicExchange(handler, "10.100.0.1"))
	if *reached != 100 {
		t.Fatalf("handler reached %d times, want 100", *reached)
	}
}

func TestPublicExchangeFailureSpikeOpensAndRecoversCircuit(t *testing.T) {
	clock := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	limiter := NewLimiter()
	limiter.now = func() time.Time { return clock }
	server := &Server{limiter: limiter}
	reached := 0
	handler := server.publicExchangeLimits(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		server.publicExchangeFailure(w, r)
	}))

	for index := 0; index < publicFailureThreshold; index++ {
		response := performPublicExchange(handler, fmt.Sprintf("10.%d.0.1", index))
		assertPublicUnavailable(t, response)
	}
	response := performPublicExchange(handler, "10.100.0.1")
	assertRateLimited(t, response)
	if reached != publicFailureThreshold {
		t.Fatalf("handler reached %d times, want %d", reached, publicFailureThreshold)
	}
	if retry := response.Header().Get("Retry-After"); retry == "" {
		t.Fatal("circuit response omitted Retry-After")
	}

	clock = clock.Add(publicCircuitDuration + time.Second)
	response = performPublicExchange(handler, "10.101.0.1")
	assertPublicUnavailable(t, response)
	if reached != publicFailureThreshold+1 {
		t.Fatalf("handler reached %d times after recovery", reached)
	}
	if len(limiter.publicFailures) != 1 {
		t.Fatalf("retained failure timestamps = %d, want 1", len(limiter.publicFailures))
	}
}

func TestPublicExchangeUnavailableStatesAreIndistinguishable(t *testing.T) {
	db := openHTTPAPITestDB(t)
	service, err := shares.New(db.Writer(), []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	ownerID, rootID := seedPublicShareOwner(t, db.Writer())

	expired, err := service.CreatePublic(context.Background(), shares.CreatePublicInput{OwnerID: ownerID, RootIDs: []string{rootID}, TTL: time.Minute, RedemptionLimit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec(`UPDATE public_shares SET expires_at = ? WHERE id = ?`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), expired.ID); err != nil {
		t.Fatal(err)
	}
	revoked, err := service.CreatePublic(context.Background(), shares.CreatePublicInput{OwnerID: ownerID, RootIDs: []string{rootID}, TTL: time.Minute, RedemptionLimit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RevokePublic(context.Background(), ownerID, revoked.ID, false); err != nil {
		t.Fatal(err)
	}
	exhausted, err := service.CreatePublic(context.Background(), shares.CreatePublicInput{OwnerID: ownerID, RootIDs: []string{rootID}, TTL: time.Minute, RedemptionLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Redeem(context.Background(), exhausted.Code); err != nil {
		t.Fatal(err)
	}

	limiter := NewLimiter()
	server := &Server{runtime: &app.Runtime{Shares: service}, limiter: limiter}
	tests := []struct {
		name string
		code string
	}{
		{name: "invalid", code: "abcde"},
		{name: "expired", code: expired.Code},
		{name: "revoked", code: revoked.Code},
		{name: "exhausted", code: exhausted.Code},
	}
	var canonical string
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{"code": test.code})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/public/exchange", bytes.NewReader(body))
			response := httptest.NewRecorder()
			server.publicExchange(response, request)
			assertPublicUnavailable(t, response)
			if strings.Contains(response.Body.String(), test.code) {
				t.Fatal("public failure response disclosed submitted code")
			}
			if canonical == "" {
				canonical = response.Body.String()
			} else if response.Body.String() != canonical {
				t.Fatalf("response differs from other unavailable states:\n%s\nwant:\n%s", response.Body.String(), canonical)
			}
		})
	}
	if len(limiter.publicFailures) != len(tests) {
		t.Fatalf("recorded failures = %d, want %d", len(limiter.publicFailures), len(tests))
	}
	for key := range limiter.buckets {
		for _, test := range tests {
			if strings.Contains(key, test.code) {
				t.Fatalf("limiter key %q retained a submitted code", key)
			}
		}
	}
}

func newPublicLimitHarness(clock *time.Time, next http.Handler) (*Server, http.Handler, *int) {
	limiter := NewLimiter()
	limiter.now = func() time.Time { return *clock }
	server := &Server{limiter: limiter}
	reached := 0
	wrapped := server.publicExchangeLimits(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		next.ServeHTTP(w, r)
	}))
	return server, wrapped, &reached
}

func performPublicExchange(handler http.Handler, address string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/public/exchange", nil)
	request.RemoteAddr = net.JoinHostPort(address, "12345")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertRateLimited(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusTooManyRequests, response.Body.String())
	}
	var problem Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "rate_limited" || problem.Status != http.StatusTooManyRequests {
		t.Fatalf("problem = %#v", problem)
	}
}

func assertPublicUnavailable(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusNotFound, response.Body.String())
	}
	var problem Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "public_share_unavailable" || problem.Status != http.StatusNotFound {
		t.Fatalf("problem = %#v", problem)
	}
}

func openHTTPAPITestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.Open(context.Background(), database.Config{Path: filepath.Join(t.TempDir(), "arca.sqlite3"), Migrations: migrations.Files})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedPublicShareOwner(t *testing.T, db *sql.DB) (string, string) {
	t.Helper()
	const (
		ownerID = "0198a000-0000-7000-8000-000000000101"
		rootID  = "0198a000-0000-7000-8000-000000000102"
	)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO users
		(id, username, username_key, email, email_key, role, state, quota_bytes, created_at, updated_at)
		VALUES (?, 'owner', 'owner', 'owner@example.com', 'owner@example.com', 'member', 'active', 1000000, ?, ?)`, ownerID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO user_policies(user_id, updated_at) VALUES (?, ?)`, ownerID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO nodes
		(id, owner_id, parent_id, kind, name, name_key, created_by, created_at, updated_at)
		VALUES (?, ?, NULL, 'folder', '', '', ?, ?, ?)`, rootID, ownerID, ownerID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE users SET root_node_id = ? WHERE id = ?`, rootID, ownerID); err != nil {
		t.Fatal(err)
	}
	return ownerID, rootID
}
