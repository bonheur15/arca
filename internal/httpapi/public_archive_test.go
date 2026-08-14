package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"arca/internal/files"
	"arca/internal/shares"
)

func createPublicArchiveSession(t *testing.T, fixture *fileHandlerFixture, roots ...string) (shares.PublicShare, shares.PublicSession) {
	t.Helper()
	created, err := fixture.shares.CreatePublic(context.Background(), shares.CreatePublicInput{
		OwnerID: fixture.owner.ID, RootIDs: roots, TTL: 10 * time.Minute, RedemptionLimit: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := fixture.shares.Redeem(context.Background(), created.Code)
	if err != nil {
		t.Fatal(err)
	}
	return created, session
}

func publicArchiveRequest(token string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/public/archive", nil)
	request.RemoteAddr = "203.0.113.80:4242"
	if token != "" {
		request.AddCookie(&http.Cookie{Name: "arca_public", Value: token, Path: "/"})
	}
	return request
}

func readZIPEntries(t *testing.T, response *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len()))
	if err != nil {
		t.Fatalf("open ZIP: %v; response=%q", err, response.Body.String())
	}
	result := make(map[string]string, len(reader.File))
	for _, file := range reader.File {
		if strings.HasPrefix(file.Name, "/") || strings.Contains(file.Name, "..") || strings.Contains(file.Name, `\`) {
			t.Fatalf("unsafe ZIP path %q", file.Name)
		}
		if file.FileInfo().IsDir() {
			result[file.Name] = ""
			continue
		}
		entry, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		contents, readErr := io.ReadAll(entry)
		closeErr := entry.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read ZIP entry %q: read=%v close=%v", file.Name, readErr, closeErr)
		}
		result[file.Name] = string(contents)
	}
	return result
}

func TestPublicArchiveStreamsOnlyRecordedLiveContentWithSafePathsAndThrottle(t *testing.T) {
	fixture := newFileHandlerFixture(t)
	if _, err := fixture.db.Writer().Exec(`UPDATE user_policies SET download_rate_bytes = 3200 WHERE user_id = ?`, fixture.owner.ID); err != nil {
		t.Fatal(err)
	}
	shared, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, fixture.owner.RootNodeID, "Shared")
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("x", 32)
	file := fixture.uploadFile(t, fixture.owner.ID, shared.ID, `evil\name.txt`, []byte(payload))
	outside := fixture.uploadFile(t, fixture.owner.ID, fixture.owner.RootNodeID, "outside.txt", []byte("must not be public"))
	_, session := createPublicArchiveSession(t, fixture, shared.ID)

	resolved, err := fixture.files.Content(context.Background(), fixture.owner.ID, file.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	blobPath, err := fixture.storage.BlobPath(resolved.StorageKey)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := os.OpenFile(blobPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blob.WriteString("SECRET-BEYOND-RECORDED-VERSION"); err != nil {
		_ = blob.Close()
		t.Fatal(err)
	}
	if err := blob.Close(); err != nil {
		t.Fatal(err)
	}

	request := publicArchiveRequest(session.Token)
	request.Header.Set("Range", "bytes=0-20")
	response := httptest.NewRecorder()
	started := time.Now()
	fixture.server.ServeHTTP(response, request)
	elapsed := time.Since(started)
	if response.Code != http.StatusOK {
		t.Fatalf("archive status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Accept-Ranges") != "none" {
		t.Fatalf("archive cache/range headers=%v", response.Header())
	}
	if response.Header().Get("Content-Range") != "" {
		t.Fatalf("generated ZIP unexpectedly served a range: %v", response.Header())
	}
	if elapsed < 5*time.Millisecond {
		t.Fatalf("configured public download rate was not applied: %s", elapsed)
	}
	entries := readZIPEntries(t, response)
	if entries["Shared/evil_name.txt"] != payload {
		t.Fatalf("public file contents=%q", entries["Shared/evil_name.txt"])
	}
	if strings.Contains(response.Body.String(), "SECRET-BEYOND-RECORDED-VERSION") {
		t.Fatal("archive disclosed bytes beyond the immutable version size")
	}
	for name, contents := range entries {
		if strings.Contains(name, outside.Name) || strings.Contains(contents, "must not be public") {
			t.Fatalf("unshared file leaked through archive entry %q", name)
		}
	}

	current, err := fixture.files.Get(context.Background(), fixture.owner.ID, file.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.files.Move(context.Background(), fixture.owner.ID, file.ID, fixture.owner.RootNodeID, current.Revision); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	fixture.server.ServeHTTP(response, publicArchiveRequest(session.Token))
	if response.Code != http.StatusOK {
		t.Fatalf("live archive status=%d body=%s", response.Code, response.Body.String())
	}
	entries = readZIPEntries(t, response)
	if _, exists := entries["Shared/evil_name.txt"]; exists {
		t.Fatal("file moved out of the live public folder remained visible")
	}
}

func TestPublicArchiveRejectsMissingExpiredAndRevokedSessionsUniformly(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *fileHandlerFixture, shares.PublicShare)
		cookie bool
	}{
		{name: "missing cookie"},
		{name: "expired", cookie: true, mutate: func(t *testing.T, fixture *fileHandlerFixture, share shares.PublicShare) {
			past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
			if _, err := fixture.db.Writer().Exec("UPDATE public_shares SET expires_at = ? WHERE id = ?", past, share.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "revoked", cookie: true, mutate: func(t *testing.T, fixture *fileHandlerFixture, share shares.PublicShare) {
			if err := fixture.shares.RevokePublic(context.Background(), fixture.owner.ID, share.ID, false); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFileHandlerFixture(t)
			root := fixture.uploadFile(t, fixture.owner.ID, fixture.owner.RootNodeID, "public.txt", []byte("public"))
			share, session := createPublicArchiveSession(t, fixture, root.ID)
			if test.mutate != nil {
				test.mutate(t, fixture, share)
			}
			token := ""
			if test.cookie {
				token = session.Token
			}
			response := httptest.NewRecorder()
			fixture.server.ServeHTTP(response, publicArchiveRequest(token))
			if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"public_share_unavailable"`) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Type") != "application/problem+json" {
				t.Fatalf("public failure headers=%v", response.Header())
			}
		})
	}
}

type revokingResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	once   sync.Once
	revoke func()
}

func (w *revokingResponseWriter) Header() http.Header { return w.header }
func (w *revokingResponseWriter) WriteHeader(int)     {}
func (w *revokingResponseWriter) Write(value []byte) (int, error) {
	w.once.Do(w.revoke)
	return w.body.Write(value)
}

func TestPublicArchiveRechecksRevocationBeforeEachFolderHeader(t *testing.T) {
	fixture := newFileHandlerFixture(t)
	root, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, fixture.owner.RootNodeID, "Public")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 100; index++ {
		name := fmt.Sprintf("a%03d-%s", index, strings.Repeat("filler", 15))
		if _, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, root.ID, name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, root.ID, "zzzz-ConfidentialSubfolder"); err != nil {
		t.Fatal(err)
	}
	share, session := createPublicArchiveSession(t, fixture, root.ID)
	request := publicArchiveRequest(session.Token)
	response := &revokingResponseWriter{header: make(http.Header)}
	response.revoke = func() {
		if err := fixture.shares.RevokePublic(context.Background(), fixture.owner.ID, share.ID, false); err != nil {
			t.Errorf("revoke public share: %v", err)
		}
	}
	fixture.server.publicArchive(response, request)
	if strings.Contains(response.body.String(), "zzzz-ConfidentialSubfolder") {
		t.Fatal("folder metadata was written after the public share was revoked")
	}
}

func TestPublicArchiveRouteRateLimitsZIPCreation(t *testing.T) {
	fixture := newFileHandlerFixture(t)
	root, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, fixture.owner.RootNodeID, "Public")
	if err != nil {
		t.Fatal(err)
	}
	_, session := createPublicArchiveSession(t, fixture, root.ID)
	for attempt := 1; attempt <= 5; attempt++ {
		response := httptest.NewRecorder()
		fixture.server.ServeHTTP(response, publicArchiveRequest(session.Token))
		if response.Code != http.StatusOK {
			t.Fatalf("attempt %d status=%d body=%s", attempt, response.Code, response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	fixture.server.ServeHTTP(response, publicArchiveRequest(session.Token))
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("sixth archive status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestCollectPublicArchiveTreeHonorsBound(t *testing.T) {
	fixture := newFileHandlerFixture(t)
	root, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, fixture.owner.RootNodeID, "Public")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, root.ID, "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, root.ID, "B"); err != nil {
		t.Fatal(err)
	}
	share, _ := createPublicArchiveSession(t, fixture, root.ID)
	nodes, err := collectPublicArchiveTree(context.Background(), fixture.db.Reader(), share.ID, root.ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("bounded public tree returned %d nodes", len(nodes))
	}
	if nodes[0].ID != root.ID || nodes[0].Kind != files.KindFolder {
		t.Fatalf("first public tree node=%+v", nodes[0])
	}
}
