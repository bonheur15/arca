package uploads

import (
	"bytes"
	"context"
	"testing"

	"arca/internal/files"
)

func TestUploadPolicyBlocksExtensionsBeforeReservation(t *testing.T) {
	db, storage, _, rootID := uploadTestFixture(t, 1<<20)
	if _, err := db.Writer().Exec(`UPDATE user_policies SET blocked_extensions = '[".exe"]' WHERE user_id = 'uploader'`); err != nil {
		t.Fatal(err)
	}
	service := newUploadService(db, storage, nil)
	_, err := service.Create(context.Background(), CreateRequest{
		ActorID: "uploader", ParentID: rootID, Name: "payload.EXE", ExpectedBytes: 10,
	})
	if files.ErrorCodeOf(err) != files.CodeFileTypeBlocked {
		t.Fatalf("blocked extension error = %v", err)
	}
	var reserved int64
	if err := db.Reader().QueryRow(`SELECT reserved_bytes FROM users WHERE id = 'uploader'`).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if reserved != 0 {
		t.Fatalf("blocked extension reserved %d bytes", reserved)
	}
}

func TestUploadPolicyChecksDetectedMIMEBeforeCommit(t *testing.T) {
	db, storage, fileService, rootID := uploadTestFixture(t, 1<<20)
	if _, err := db.Writer().Exec(`UPDATE user_policies SET allowed_mime_groups = '["image"]' WHERE user_id = 'uploader'`); err != nil {
		t.Fatal(err)
	}
	service := newUploadService(db, storage, nil)
	payload := []byte("plain text is not an image")
	upload, err := service.Create(context.Background(), CreateRequest{
		ActorID: "uploader", ParentID: rootID, Name: "note.txt", ExpectedBytes: int64(len(payload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Patch(context.Background(), PatchRequest{
		ActorID: "uploader", UploadID: upload.ID, Offset: 0, ContentLength: int64(len(payload)), Body: bytes.NewReader(payload),
	})
	if files.ErrorCodeOf(err) != files.CodeFileTypeBlocked {
		t.Fatalf("blocked MIME error = %v", err)
	}
	failed, err := service.Head(context.Background(), "uploader", upload.ID)
	if err != nil {
		t.Fatal(err)
	}
	if failed.State != StateFailed || failed.ErrorCode == nil || *failed.ErrorCode != string(files.CodeFileTypeBlocked) {
		t.Fatalf("unexpected failed upload: %+v", failed)
	}
	quota, err := fileService.Quota(context.Background(), "uploader")
	if err != nil {
		t.Fatal(err)
	}
	if quota.StoredReservedBytes != 0 || quota.StoredUsedBytes != 0 || quota.ActualReservedBytes != 0 || quota.ActualUsedBytes != 0 {
		t.Fatalf("blocked MIME retained quota: %+v", quota)
	}
	if size, err := storage.StagingSize(upload.ID); err != nil || size != 0 {
		t.Fatalf("blocked MIME staging size = %d, error = %v", size, err)
	}
}
