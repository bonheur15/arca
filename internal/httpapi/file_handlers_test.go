package httpapi

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"arca/internal/accounts"
	"arca/internal/app"
	"arca/internal/audit"
	"arca/internal/config"
	"arca/internal/database"
	"arca/internal/files"
	"arca/internal/shares"
	"arca/internal/uploads"
	"arca/migrations"

	"github.com/go-chi/chi/v5"
)

type fileHandlerFixture struct {
	server    *Server
	db        *database.DB
	storage   *uploads.LocalStorage
	files     *files.Service
	uploads   *uploads.Service
	shares    *shares.Service
	repo      *accounts.Repository
	owner     *accounts.User
	recipient *accounts.User
	admin     *accounts.User
}

func newFileHandlerFixture(t *testing.T) *fileHandlerFixture {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	db, err := database.Open(ctx, database.Config{
		Path: filepath.Join(root, "database", "arca.sqlite3"), Migrations: migrations.Files, MaxReadConns: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := db.Writer().Exec(`INSERT INTO instance_settings
		(singleton, instance_id, initialized, name, public_url, filesystem_reserve_bytes, created_at, updated_at)
		VALUES (1, 'http-file-test', 1, 'HTTP file test', 'https://arca.test', 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	repo := accounts.NewRepository(db.Writer())
	createUser := func(username string, role accounts.Role) *accounts.User {
		user, createErr := repo.CreateUser(ctx, accounts.CreateUserParams{
			Username: username, Email: username + "@example.test", Role: role,
			State: accounts.StateActive, QuotaBytes: 1 << 30, Policy: accounts.DefaultPolicy(),
		})
		if createErr != nil {
			t.Fatal(createErr)
		}
		return user
	}
	owner := createUser("owner", accounts.RoleMember)
	recipient := createUser("recipient", accounts.RoleMember)
	admin := createUser("admin", accounts.RoleSuperadmin)
	storage, err := uploads.NewLocalStorage(root)
	if err != nil {
		t.Fatal(err)
	}
	fileService := files.NewService(db, files.ServiceOptions{})
	uploadService := uploads.NewService(db, storage, uploads.ServiceOptions{MaxChunkBytes: 32})
	shareService, err := shares.New(db.Writer(), bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	recorder := audit.NewSQLRecorder(db.Writer())
	accountService := accounts.NewService(repo, nil, nil, recorder)
	configRuntime := &config.Runtime{File: config.FileConfig{PublicURL: "http://localhost:8080"}}
	runtime := &app.Runtime{
		Config:   configRuntime,
		Database: db, Accounts: accountService, AccountRepo: repo, Files: fileService, Uploads: uploadService,
		Storage: storage, Shares: shareService, Audit: recorder,
	}
	server := &Server{
		runtime: runtime, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), limiter: NewLimiter(),
		idempotency: NewIdempotencyStore(db.Writer()), events: NewHub(),
	}
	server.router = server.routes()
	return &fileHandlerFixture{server: server, db: db, storage: storage, files: fileService, uploads: uploadService,
		shares: shareService, repo: repo, owner: owner, recipient: recipient, admin: admin}
}

func (f *fileHandlerFixture) uploadFile(t *testing.T, actorID, parentID, name string, contents []byte) files.Node {
	t.Helper()
	upload, err := f.uploads.Create(context.Background(), uploads.CreateRequest{
		ActorID: actorID, ParentID: parentID, Name: name, ExpectedBytes: int64(len(contents)), ConflictMode: uploads.ConflictFail,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) == 0 {
		upload, err = f.uploads.Complete(context.Background(), actorID, upload.ID)
	} else {
		upload, err = f.uploads.Patch(context.Background(), uploads.PatchRequest{
			ActorID: actorID, UploadID: upload.ID, Offset: 0, ContentLength: int64(len(contents)), Body: bytes.NewReader(contents),
		})
	}
	if err != nil || upload.NodeID == nil {
		t.Fatalf("complete upload: upload=%+v err=%v", upload, err)
	}
	node, err := f.files.Get(context.Background(), actorID, *upload.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func requestAs(method, target string, body io.Reader, user *accounts.User) *http.Request {
	request := httptest.NewRequest(method, target, body)
	request.RemoteAddr = "203.0.113.40:1234"
	return request.WithContext(WithPrincipal(request.Context(), Principal{
		UserID: user.ID, Role: string(user.Role), State: string(user.State), CookieAuth: true,
	}))
}

func withNodeID(request *http.Request, nodeID string) *http.Request {
	route := chi.NewRouteContext()
	route.URLParams.Add("nodeID", nodeID)
	return request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
}

func TestSupportFileBrowsingIsReadOnlyAndAudited(t *testing.T) {
	fixture := newFileHandlerFixture(t)
	file := fixture.uploadFile(t, fixture.owner.ID, fixture.owner.RootNodeID, "report.txt", []byte("support evidence"))
	grant, err := fixture.repo.CreateSupportAccess(context.Background(), fixture.admin.ID, fixture.owner.ID,
		"Investigating a reported preview failure", time.Now().UTC().Add(15*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	listing := httptest.NewRecorder()
	fixture.server.listNodes(listing, requestAs(http.MethodGet,
		"/api/v1/nodes?support_user="+fixture.owner.ID, nil, fixture.admin))
	if listing.Code != http.StatusOK {
		t.Fatalf("support listing status=%d body=%s", listing.Code, listing.Body.String())
	}

	download := httptest.NewRecorder()
	request := withNodeID(requestAs(http.MethodGet,
		"/api/v1/files/"+file.ID+"/content?support_user="+fixture.owner.ID, nil, fixture.admin), file.ID)
	fixture.server.content(download, request)
	if download.Code != http.StatusOK || download.Body.String() != "support evidence" {
		t.Fatalf("support download status=%d body=%q", download.Code, download.Body.String())
	}

	mutation := httptest.NewRecorder()
	fixture.server.createFolder(mutation, requestAs(http.MethodPost, "/api/v1/folders",
		strings.NewReader(`{"parent_id":"`+fixture.owner.RootNodeID+`","name":"Forbidden"}`), fixture.admin))
	if mutation.Code != http.StatusForbidden {
		t.Fatalf("support mutation status=%d body=%s", mutation.Code, mutation.Body.String())
	}

	var folderEvents, downloadEvents int
	if err := fixture.db.Reader().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE actor_id = ? AND action =
		'support_access.folder_opened' AND json_extract(metadata, '$.support_access_id') = ?`, fixture.admin.ID, grant.ID).Scan(&folderEvents); err != nil {
		t.Fatal(err)
	}
	if err := fixture.db.Reader().QueryRow(`SELECT COUNT(*) FROM audit_events WHERE actor_id = ? AND target_id = ?
		AND action = 'support_access.content_downloaded'`, fixture.admin.ID, file.ID).Scan(&downloadEvents); err != nil {
		t.Fatal(err)
	}
	if folderEvents != 1 || downloadEvents != 1 {
		t.Fatalf("support audit folder/download=%d/%d", folderEvents, downloadEvents)
	}
}

func TestSupportAccessCanBeReadAndExplicitlyRevoked(t *testing.T) {
	fixture := newFileHandlerFixture(t)
	grant, err := fixture.repo.CreateSupportAccess(context.Background(), fixture.admin.ID, fixture.owner.ID,
		"Investigating a reported download failure", time.Now().UTC().Add(15*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	read := httptest.NewRecorder()
	fixture.server.activeSupportAccess(read, requestAs(http.MethodGet, "/api/v1/support-access", nil, fixture.admin))
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), grant.ID) || !strings.Contains(read.Body.String(), fixture.owner.Username) {
		t.Fatalf("active support status=%d body=%s", read.Code, read.Body.String())
	}
	revoke := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/support-access/"+grant.ID, nil)
	request = requestAs(http.MethodDelete, request.URL.String(), nil, fixture.admin)
	route := chi.NewRouteContext()
	route.URLParams.Add("accessID", grant.ID)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
	fixture.server.revokeSupportAccess(revoke, request)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke support status=%d body=%s", revoke.Code, revoke.Body.String())
	}
	if _, err := fixture.repo.GetActiveSupportAccess(context.Background(), fixture.admin.ID); !errors.Is(err, accounts.ErrNotFound) {
		t.Fatalf("support grant remained active: %v", err)
	}
}

func TestSaveCopyCreatesRecipientOwnedBlob(t *testing.T) {
	fixture := newFileHandlerFixture(t)
	source := fixture.uploadFile(t, fixture.owner.ID, fixture.owner.RootNodeID, "shared.txt", []byte("private copy"))
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := fixture.db.Writer().Exec(`INSERT INTO shares
		(id, owner_id, permission, created_at, updated_at) VALUES ('save-copy-share', ?, 'viewer', ?, ?)`,
		fixture.owner.ID, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.Writer().Exec(`INSERT INTO share_roots(share_id, node_id) VALUES ('save-copy-share', ?)`, source.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.Writer().Exec(`INSERT INTO share_recipients(share_id, user_id) VALUES ('save-copy-share', ?)`, fixture.recipient.ID); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	request := withNodeID(requestAs(http.MethodPost, "/api/v1/nodes/"+source.ID+"/save-copy",
		strings.NewReader(`{"destinationId":"`+fixture.recipient.RootNodeID+`","name":"mine.txt","conflictMode":"fail"}`), fixture.recipient), source.ID)
	fixture.server.saveNodeCopy(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("save-copy status=%d body=%s", response.Code, response.Body.String())
	}
	var result uploads.Upload
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.NodeID == nil {
		t.Fatalf("decode save-copy result=%+v err=%v", result, err)
	}
	node, err := fixture.files.Get(context.Background(), fixture.recipient.ID, *result.NodeID)
	if err != nil || node.OwnerID != fixture.recipient.ID || node.Name != "mine.txt" {
		t.Fatalf("saved node=%+v err=%v", node, err)
	}
	content, err := fixture.files.Content(context.Background(), fixture.recipient.ID, node.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := fixture.storage.OpenBlob(content.StorageKey)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || string(data) != "private copy" {
		t.Fatalf("saved contents=%q read=%v close=%v", data, readErr, closeErr)
	}
}

func TestBulkTrashRejectsStaleBatchWithoutPartialMutation(t *testing.T) {
	fixture := newFileHandlerFixture(t)
	first, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, fixture.owner.RootNodeID, "First")
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, fixture.owner.RootNodeID, "Second")
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	body := `{"action":"trash","items":[{"id":"` + first.ID + `","revision":1},{"id":"` + second.ID + `","revision":2}]}`
	fixture.server.bulkNodes(response, requestAs(http.MethodPost, "/api/v1/nodes/bulk", strings.NewReader(body), fixture.owner))
	if response.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale bulk status=%d body=%s", response.Code, response.Body.String())
	}
	for _, nodeID := range []string{first.ID, second.ID} {
		var trashed *string
		if err := fixture.db.Reader().QueryRow("SELECT trashed_at FROM nodes WHERE id = ?", nodeID).Scan(&trashed); err != nil {
			t.Fatal(err)
		}
		if trashed != nil {
			t.Fatalf("node %s was partially trashed", nodeID)
		}
	}

	response = httptest.NewRecorder()
	body = `{"action":"trash","items":[{"id":"` + first.ID + `","if_match":"1"},{"id":"` + second.ID + `","revision":1}]}`
	fixture.server.bulkNodes(response, requestAs(http.MethodPost, "/api/v1/nodes/bulk", strings.NewReader(body), fixture.owner))
	if response.Code != http.StatusOK {
		t.Fatalf("valid bulk status=%d body=%s", response.Code, response.Body.String())
	}
	for _, nodeID := range []string{first.ID, second.ID} {
		var trashed *string
		if err := fixture.db.Reader().QueryRow("SELECT trashed_at FROM nodes WHERE id = ?", nodeID).Scan(&trashed); err != nil || trashed == nil {
			t.Fatalf("node %s trash=%v err=%v", nodeID, trashed, err)
		}
	}
}

func TestBulkMoveRestoreAndPurgeLifecycle(t *testing.T) {
	fixture := newFileHandlerFixture(t)
	destination, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, fixture.owner.RootNodeID, "Destination")
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, fixture.owner.RootNodeID, "First")
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, fixture.owner.RootNodeID, "Second")
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		response := httptest.NewRecorder()
		fixture.server.bulkNodes(response, requestAs(http.MethodPost, "/api/v1/nodes/bulk", strings.NewReader(body), fixture.owner))
		if response.Code != http.StatusOK {
			t.Fatalf("bulk status=%d body=%s request=%s", response.Code, response.Body.String(), body)
		}
		return response
	}
	items := func(revision int) string {
		return `[{"id":"` + first.ID + `","revision":` + strconv.Itoa(revision) + `},{"id":"` + second.ID + `","revision":` + strconv.Itoa(revision) + `}]`
	}
	mutate(`{"action":"move","destination_id":"` + destination.ID + `","items":` + items(1) + `}`)
	for _, nodeID := range []string{first.ID, second.ID} {
		var parent string
		if err := fixture.db.Reader().QueryRow("SELECT parent_id FROM nodes WHERE id = ?", nodeID).Scan(&parent); err != nil || parent != destination.ID {
			t.Fatalf("node %s parent=%s err=%v", nodeID, parent, err)
		}
	}
	mutate(`{"action":"trash","items":` + items(2) + `}`)
	mutate(`{"action":"restore","items":` + items(3) + `}`)
	mutate(`{"action":"trash","items":` + items(4) + `}`)
	purge := mutate(`{"action":"purge","items":` + items(5) + `}`)
	if !strings.Contains(purge.Body.String(), `"nodes_deleted":2`) {
		t.Fatalf("purge summary=%s", purge.Body.String())
	}
	for _, nodeID := range []string{first.ID, second.ID} {
		var count int
		if err := fixture.db.Reader().QueryRow("SELECT COUNT(*) FROM nodes WHERE id = ?", nodeID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("node %s count=%d err=%v", nodeID, count, err)
		}
	}
}

func TestArchiveStreamsSafePathsAndFileBodies(t *testing.T) {
	fixture := newFileHandlerFixture(t)
	if _, err := fixture.db.Writer().Exec(`UPDATE user_policies SET download_rate_bytes = 100000000 WHERE user_id = ?`, fixture.owner.ID); err != nil {
		t.Fatal(err)
	}
	unsafe := fixture.uploadFile(t, fixture.owner.ID, fixture.owner.RootNodeID, `evil\name.txt`, []byte("root file"))
	folder, err := fixture.files.CreateFolder(context.Background(), fixture.owner.ID, fixture.owner.RootNodeID, "Folder")
	if err != nil {
		t.Fatal(err)
	}
	fixture.uploadFile(t, fixture.owner.ID, folder.ID, "nested.txt", []byte("nested file"))

	response := httptest.NewRecorder()
	body := `{"nodeIds":["` + unsafe.ID + `","` + folder.ID + `"],"name":"bundle"}`
	fixture.server.archiveNodes(response, requestAs(http.MethodPost, "/api/v1/nodes/archive", strings.NewReader(body), fixture.owner))
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("archive status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	reader, err := zip.NewReader(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	contents := make(map[string]string)
	for _, item := range reader.File {
		if strings.HasPrefix(item.Name, "/") || strings.Contains(item.Name, "..") || strings.Contains(item.Name, `\`) {
			t.Fatalf("unsafe archive path %q", item.Name)
		}
		if item.FileInfo().IsDir() {
			contents[item.Name] = ""
			continue
		}
		entry, err := item.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(entry)
		closeErr := entry.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read %s: read=%v close=%v", item.Name, readErr, closeErr)
		}
		contents[item.Name] = string(data)
	}
	if contents["evil_name.txt"] != "root file" || contents["Folder/nested.txt"] != "nested file" {
		t.Fatalf("archive contents=%v", contents)
	}
}
