package httpapi

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestByteRateReaderBoundsChunkAndHonorsCancellation(t *testing.T) {
	t.Parallel()
	payload := bytes.Repeat([]byte("x"), 64)
	ctx, cancel := context.WithCancel(context.Background())
	reader := newByteRateReader(ctx, bytes.NewReader(payload), 32)
	reader.(*byteRateReader).started = time.Now().Add(-time.Second)
	buffer := make([]byte, 64)
	read, err := reader.Read(buffer)
	if err != nil || read != 32 {
		t.Fatalf("first read = %d, %v", read, err)
	}
	cancel()
	if _, err := reader.Read(buffer); err == nil {
		t.Fatal("cancelled rate reader returned no error")
	}

	unlimited := newByteRateReader(context.Background(), bytes.NewReader(payload), 0)
	read, err = io.ReadFull(unlimited, buffer)
	if err != nil || read != len(payload) {
		t.Fatalf("unlimited reader = %d, %v", read, err)
	}

	throttled := newByteRateReader(context.Background(), bytes.NewReader(payload), 6400)
	started := time.Now()
	if _, err := throttled.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 5*time.Millisecond {
		t.Fatalf("rate reader returned too early: %s", elapsed)
	}
}
