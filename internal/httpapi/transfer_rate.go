package httpapi

import (
	"context"
	"database/sql"
	"io"
	"time"
)

type byteRateReader struct {
	ctx     context.Context
	reader  io.Reader
	rate    int64
	started time.Time
	read    int64
}

func newByteRateReader(ctx context.Context, reader io.Reader, bytesPerSecond int64) io.Reader {
	if bytesPerSecond <= 0 {
		return reader
	}
	return &byteRateReader{ctx: ctx, reader: reader, rate: bytesPerSecond, started: time.Now()}
}

func (r *byteRateReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	chunk := int64(len(buffer))
	if chunk > 64<<10 {
		chunk = 64 << 10
	}
	if chunk > r.rate {
		chunk = r.rate
	}
	if chunk < 1 {
		chunk = 1
	}
	read, err := r.reader.Read(buffer[:chunk])
	r.read += int64(read)
	seconds := r.read / r.rate
	remainder := r.read % r.rate
	target := time.Duration(seconds)*time.Second + time.Duration(remainder*int64(time.Second)/r.rate)
	wait := target - time.Since(r.started)
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-r.ctx.Done():
			if read > 0 {
				return read, nil
			}
			return 0, r.ctx.Err()
		case <-timer.C:
		}
	}
	return read, err
}

type rateReadSeeker struct {
	io.ReadSeeker
	reader io.Reader
}

func (r *rateReadSeeker) Read(buffer []byte) (int, error) { return r.reader.Read(buffer) }

func newRateReadSeeker(ctx context.Context, seeker io.ReadSeeker, bytesPerSecond int64) io.ReadSeeker {
	if bytesPerSecond <= 0 {
		return seeker
	}
	return &rateReadSeeker{ReadSeeker: seeker, reader: newByteRateReader(ctx, seeker, bytesPerSecond)}
}

func (s *Server) uploadRate(ctx context.Context, userID string) int64 {
	return s.policyRate(ctx, userID, true)
}

func (s *Server) downloadRate(ctx context.Context, userID string) int64 {
	return s.policyRate(ctx, userID, false)
}

func (s *Server) policyRate(ctx context.Context, userID string, upload bool) int64 {
	if userID == "" {
		return 0
	}
	query := `SELECT download_rate_bytes FROM user_policies WHERE user_id = ?`
	if upload {
		query = `SELECT upload_rate_bytes FROM user_policies WHERE user_id = ?`
	}
	var value sql.NullInt64
	if err := s.runtime.Database.Reader().QueryRowContext(ctx, query, userID).Scan(&value); err != nil || !value.Valid || value.Int64 <= 0 {
		return 0
	}
	return value.Int64
}
