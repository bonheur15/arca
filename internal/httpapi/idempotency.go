package httpapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type StoredResponse struct {
	Status  int
	Headers http.Header
	Body    []byte
}

type IdempotencyStore struct {
	db  *sql.DB
	now func() time.Time
}

func NewIdempotencyStore(db *sql.DB) *IdempotencyStore {
	return &IdempotencyStore{db: db, now: time.Now}
}

func (s *IdempotencyStore) Lookup(ctx context.Context, actor, key string, requestHash []byte) (*StoredResponse, error) {
	var storedHash, body []byte
	var status int
	var headersJSON string
	err := s.db.QueryRowContext(ctx, `SELECT request_hash, response_status, response_headers, response_body
        FROM idempotency_keys WHERE actor_key = ? AND idempotency_key = ? AND expires_at > ?`, actor, key, stamp(s.now())).
		Scan(&storedHash, &status, &headersJSON, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !constantBytesEqual(storedHash, requestHash) {
		return nil, Problem{Status: http.StatusConflict, Code: "idempotency_mismatch", Title: "Idempotency key conflict", Detail: "This key was already used with a different request."}
	}
	headers := make(http.Header)
	if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
		return nil, err
	}
	return &StoredResponse{Status: status, Headers: headers, Body: body}, nil
}

func (s *IdempotencyStore) Save(ctx context.Context, actor, key string, requestHash []byte, response StoredResponse) error {
	headers := make(http.Header)
	for _, name := range []string{"Content-Type", "ETag", "Location", "Tus-Resumable"} {
		if value := response.Headers.Get(name); value != "" {
			headers.Set(name, value)
		}
	}
	encoded, err := json.Marshal(headers)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	_, err = s.db.ExecContext(ctx, `INSERT INTO idempotency_keys
        (actor_key, idempotency_key, request_hash, response_status, response_headers, response_body, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(actor_key, idempotency_key) DO NOTHING`, actor, key, requestHash, response.Status, string(encoded), response.Body, stamp(now.Add(24*time.Hour)), stamp(now))
	return err
}

func RequestDigest(r *http.Request, maximum int64) ([]byte, []byte, error) {
	if maximum <= 0 {
		maximum = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maximum+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(body)) > maximum {
		return nil, nil, Problem{Status: http.StatusRequestEntityTooLarge, Code: "body_too_large", Title: "Request body too large"}
	}
	canonical := strings.Join([]string{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, r.Header.Get("Content-Type"), hex.EncodeToString(body)}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	return digest[:], body, nil
}

func constantBytesEqual(first, second []byte) bool {
	if len(first) != len(second) {
		return false
	}
	var result byte
	for index := range first {
		result |= first[index] ^ second[index]
	}
	return result == 0
}

func stamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
