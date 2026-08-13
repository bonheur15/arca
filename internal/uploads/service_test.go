package uploads

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"arca/internal/database"
	"arca/internal/files"
	"arca/migrations"
)

var uploadTestNow = time.Date(2026, 8, 14, 15, 0, 0, 0, time.UTC)

func uploadTestFixture(t *testing.T, quota int64) (*database.DB, *LocalStorage, *files.Service, string) {
	t.Helper()
	dataDir := t.TempDir()
	db, err := database.Open(context.Background(), database.Config{
		Path:         filepath.Join(dataDir, "database", "arca.sqlite3"),
		Migrations:   migrations.Files,
		MaxReadConns: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	now := timeText(uploadTestNow)
	if _, err := db.Writer().Exec(`INSERT INTO instance_settings
        (singleton, instance_id, initialized, name, public_url, filesystem_reserve_bytes, created_at, updated_at)
        VALUES (1, 'upload-test', 1, 'Upload Test', 'https://arca.test', 0, ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec(`INSERT INTO users
        (id, username, username_key, email, email_key, role, state, quota_bytes, created_at, updated_at)
        VALUES ('uploader', 'uploader', 'uploader', 'upload@example.test', 'upload@example.test', 'member', 'active', ?, ?, ?)`, quota, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Writer().Exec("INSERT INTO user_policies(user_id, updated_at) VALUES ('uploader', ?)", now); err != nil {
		t.Fatal(err)
	}
	fileService := files.NewService(db, files.ServiceOptions{Now: func() time.Time { return uploadTestNow }})
	root, err := fileService.CreateUserRoot(context.Background(), "uploader")
	if err != nil {
		t.Fatal(err)
	}
	storage, err := NewLocalStorage(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	return db, storage, fileService, root.ID
}

func newUploadService(db *database.DB, storage Storage, hook FinalizeHook) *Service {
	return NewService(db, storage, ServiceOptions{Now: func() time.Time { return uploadTestNow }, FinalizeHook: hook})
}

func TestUploadPatchChecksumFinalizeAndCancel(t *testing.T) {
	db, storage, fileService, rootID := uploadTestFixture(t, 1<<20)
	service := newUploadService(db, storage, nil)
	upload, err := service.Create(context.Background(), CreateRequest{
		ActorID: "uploader", ParentID: rootID, Name: "hello.txt", ExpectedBytes: 11, ConflictMode: ConflictFail,
	})
	if err != nil {
		t.Fatal(err)
	}
	var reserved int64
	if err := db.Reader().QueryRow("SELECT reserved_bytes FROM users WHERE id = 'uploader'").Scan(&reserved); err != nil || reserved != 11 {
		t.Fatalf("reserved = %d, error = %v", reserved, err)
	}
	first := []byte("hello")
	digest := sha256.Sum256(first)
	upload, err = service.Patch(context.Background(), PatchRequest{
		ActorID: "uploader", UploadID: upload.ID, Offset: 0, ContentLength: int64(len(first)), Body: bytes.NewReader(first),
		ChecksumAlgorithm: "sha256", Checksum: digest[:],
	})
	if err != nil || upload.CommittedBytes != 5 {
		t.Fatalf("first patch = %+v, error = %v", upload, err)
	}
	if _, err := service.Patch(context.Background(), PatchRequest{
		ActorID: "uploader", UploadID: upload.ID, Offset: 0, ContentLength: 1, Body: bytes.NewReader([]byte("x")),
	}); files.ErrorCodeOf(err) != files.CodeOffsetMismatch {
		t.Fatalf("stale offset error = %v", err)
	}
	badDigest := make([]byte, sha256.Size)
	if _, err := service.Patch(context.Background(), PatchRequest{
		ActorID: "uploader", UploadID: upload.ID, Offset: 5, ContentLength: 6, Body: bytes.NewReader([]byte(" world")),
		ChecksumAlgorithm: "sha256", Checksum: badDigest,
	}); files.ErrorCodeOf(err) != files.CodeChecksumMismatch {
		t.Fatalf("bad checksum error = %v", err)
	}
	if size, err := storage.StagingSize(upload.ID); err != nil || size != 5 {
		t.Fatalf("staging size = %d, error = %v", size, err)
	}

	upload, err = service.Patch(context.Background(), PatchRequest{
		ActorID: "uploader", UploadID: upload.ID, Offset: 5, ContentLength: 6, Body: bytes.NewReader([]byte(" world")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if upload.State != StateCompleted || upload.NodeID == nil || upload.CurrentVersionID == nil {
		t.Fatalf("completed upload = %+v", upload)
	}
	content, err := fileService.Content(context.Background(), "uploader", *upload.NodeID, "")
	if err != nil {
		t.Fatal(err)
	}
	blobPath, err := storage.BlobPath(content.StorageKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(blobPath)
	if err != nil || string(data) != "hello world" {
		t.Fatalf("blob = %q, error = %v", data, err)
	}
	var used int64
	if err := db.Reader().QueryRow("SELECT used_bytes, reserved_bytes FROM users WHERE id = 'uploader'").Scan(&used, &reserved); err != nil || used != 11 || reserved != 0 {
		t.Fatalf("used/reserved = %d/%d, error = %v", used, reserved, err)
	}
	head, err := service.Head(context.Background(), "uploader", upload.ID)
	if err != nil || head.NodeID == nil || *head.NodeID != *upload.NodeID {
		t.Fatalf("idempotent head = %+v, error = %v", head, err)
	}

	cancelled, err := service.Create(context.Background(), CreateRequest{ActorID: "uploader", ParentID: rootID, Name: "cancel.bin", ExpectedBytes: 9})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Cancel(context.Background(), "uploader", cancelled.ID); err != nil {
		t.Fatal(err)
	}
	if head, err := service.Head(context.Background(), "uploader", cancelled.ID); err != nil || head.State != StateCancelled {
		t.Fatalf("cancelled = %+v, error = %v", head, err)
	}
}

func TestFinalizeRecoversAfterBlobRename(t *testing.T) {
	db, storage, _, rootID := uploadTestFixture(t, 1<<20)
	crash := errors.New("simulated crash after rename")
	var once sync.Once
	hook := func(_ context.Context, point FinalizePoint, _ Upload) error {
		var err error
		if point == AfterBlobRename {
			once.Do(func() { err = crash })
		}
		return err
	}
	service := newUploadService(db, storage, hook)
	upload, err := service.Create(context.Background(), CreateRequest{ActorID: "uploader", ParentID: rootID, Name: "recover.txt", ExpectedBytes: 7})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Patch(context.Background(), PatchRequest{ActorID: "uploader", UploadID: upload.ID, Offset: 0, ContentLength: 7, Body: bytes.NewReader([]byte("recover"))}); !errors.Is(err, crash) {
		t.Fatalf("patch error = %v", err)
	}
	if head, err := service.Head(context.Background(), "uploader", upload.ID); err != nil || head.State != StateFinalizing {
		t.Fatalf("pre-reconcile upload = %+v, error = %v", head, err)
	}
	recovered := newUploadService(db, storage, nil)
	if err := recovered.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	head, err := recovered.Head(context.Background(), "uploader", upload.ID)
	if err != nil || head.State != StateCompleted || head.NodeID == nil {
		t.Fatalf("recovered upload = %+v, error = %v", head, err)
	}
}

func TestReconcileTruncatesUncommittedTailAndQuarantinesOrphan(t *testing.T) {
	db, storage, _, rootID := uploadTestFixture(t, 1<<20)
	service := newUploadService(db, storage, nil)
	upload, err := service.Create(context.Background(), CreateRequest{ActorID: "uploader", ParentID: rootID, Name: "tail.bin", ExpectedBytes: 8})
	if err != nil {
		t.Fatal(err)
	}
	staging, err := storage.OpenStaging(upload.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staging.Write([]byte("uncommitted")); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(staging.Sync(), staging.Close()); err != nil {
		t.Fatal(err)
	}

	orphanID := "0198a123-4567-7890-8123-456789abcdef"
	orphan, err := storage.OpenStaging(orphanID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orphan.Write([]byte("orphan")); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(orphan.Sync(), orphan.Close()); err != nil {
		t.Fatal(err)
	}
	if err := storage.Finalize(orphanID, orphanID); err != nil {
		t.Fatal(err)
	}

	if err := service.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if size, err := storage.StagingSize(upload.ID); err != nil || size != 0 {
		t.Fatalf("reconciled staging size = %d, error = %v", size, err)
	}
	keys, err := storage.ListBlobKeys()
	if err != nil || len(keys) != 0 {
		t.Fatalf("blob keys after quarantine = %v, error = %v", keys, err)
	}
	if _, err := os.Stat(filepath.Join(storage.quarantine, orphanID)); err != nil {
		t.Fatalf("quarantined orphan: %v", err)
	}
}

func TestConcurrentQuotaReservationAllowsOnlyOneWinner(t *testing.T) {
	db, storage, _, rootID := uploadTestFixture(t, 10)
	service := newUploadService(db, storage, nil)
	start := make(chan struct{})
	errorsByUpload := make(chan error, 2)
	for _, name := range []string{"one.bin", "two.bin"} {
		name := name
		go func() {
			<-start
			_, err := service.Create(context.Background(), CreateRequest{ActorID: "uploader", ParentID: rootID, Name: name, ExpectedBytes: 7})
			errorsByUpload <- err
		}()
	}
	close(start)
	var successes, quotaErrors int
	for range 2 {
		err := <-errorsByUpload
		if err == nil {
			successes++
		} else if files.ErrorCodeOf(err) == files.CodeQuota {
			quotaErrors++
		} else {
			t.Fatalf("unexpected create error: %v", err)
		}
	}
	if successes != 1 || quotaErrors != 1 {
		t.Fatalf("success/quota = %d/%d", successes, quotaErrors)
	}
	var reserved int64
	if err := db.Reader().QueryRow("SELECT reserved_bytes FROM users WHERE id = 'uploader'").Scan(&reserved); err != nil || reserved != 7 {
		t.Fatalf("reserved = %d, error = %v", reserved, err)
	}
}

func TestZeroByteUploadAndChecksumParsing(t *testing.T) {
	db, storage, _, rootID := uploadTestFixture(t, 10)
	service := newUploadService(db, storage, nil)
	upload, err := service.Create(context.Background(), CreateRequest{ActorID: "uploader", ParentID: rootID, Name: "empty.txt", ExpectedBytes: 0})
	if err != nil {
		t.Fatal(err)
	}
	upload, err = service.Complete(context.Background(), "uploader", upload.ID)
	if err != nil || upload.State != StateCompleted {
		t.Fatalf("empty completion = %+v, error = %v", upload, err)
	}
	digest := sha256.Sum256([]byte("arca"))
	parsed, err := ParseChecksum("sha256 " + base64.StdEncoding.EncodeToString(digest[:]))
	if err != nil || parsed.Algorithm != "sha256" || !bytes.Equal(parsed.Digest, digest[:]) {
		t.Fatalf("parsed checksum = %+v, error = %v", parsed, err)
	}
	if _, err := ParseChecksum("md5 Zm9v"); files.ErrorCodeOf(err) != files.CodeInvalid {
		t.Fatalf("invalid checksum error = %v", err)
	}
}

func TestLocalStorageRejectsStagingSymlink(t *testing.T) {
	storage, err := NewLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("do not overwrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	id := "0198a123-4567-7890-8123-456789abcdef"
	if err := os.Symlink(target, filepath.Join(storage.staging, id+".part")); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.OpenStaging(id); err == nil {
		t.Fatal("OpenStaging followed a symlink")
	}
}
