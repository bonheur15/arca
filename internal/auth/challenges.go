package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type challengeTokenPayload struct {
	Nonce     string `json:"n"`
	IPAddress string `json:"ip,omitempty"`
	UserAgent string `json:"ua,omitempty"`
}

type ChallengeStore struct {
	db     *sql.DB
	secret []byte
	now    func() time.Time
}

func NewChallengeStore(db *sql.DB, secret []byte) (*ChallengeStore, error) {
	if db == nil {
		return nil, errors.New("auth: challenge database is required")
	}
	if len(secret) < 32 {
		return nil, errors.New("auth: challenge secret must contain at least 32 bytes")
	}
	return &ChallengeStore{db: db, secret: append([]byte(nil), secret...), now: time.Now}, nil
}

func (s *ChallengeStore) Create(ctx context.Context, emailKey, magicAuthID, radarID, ipAddress, userAgent string, expiresAt time.Time) (Challenge, string, error) {
	if emailKey == "" || !expiresAt.After(s.now()) {
		return Challenge{}, "", ErrInvalidCredentials
	}
	token, err := s.createToken(ipAddress, userAgent)
	if err != nil {
		return Challenge{}, "", fmt.Errorf("auth: create challenge token: %w", err)
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Challenge{}, "", fmt.Errorf("auth: create challenge id: %w", err)
	}
	now := s.now().UTC()
	challenge := Challenge{
		ID: id.String(), EmailKey: emailKey, MagicAuthID: magicAuthID,
		RadarAuthAttemptID: radarID, OriginalIPAddress: ipAddress,
		OriginalUserAgent: truncate(userAgent, 512), ExpiresAt: expiresAt.UTC(), CreatedAt: now,
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO auth_challenges (
			id, email_key, magic_auth_id, radar_attempt_id, token_hash, expires_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`, challenge.ID, challenge.EmailKey,
		nullIfEmpty(challenge.MagicAuthID), nullIfEmpty(challenge.RadarAuthAttemptID),
		s.hashToken(token), formatTime(challenge.ExpiresAt), formatTime(now))
	if err != nil {
		return Challenge{}, "", fmt.Errorf("auth: persist challenge: %w", err)
	}
	return challenge, token, nil
}

func (s *ChallengeStore) Get(ctx context.Context, token string) (*Challenge, error) {
	payload, err := s.decodeToken(token)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	var challenge Challenge
	var magicID, radarID, consumed sql.NullString
	var expires, created string
	err = s.db.QueryRowContext(ctx, `
		SELECT id, email_key, magic_auth_id, radar_attempt_id, expires_at, consumed_at, created_at
		FROM auth_challenges WHERE token_hash = ?`, s.hashToken(token)).Scan(
		&challenge.ID, &challenge.EmailKey, &magicID, &radarID, &expires, &consumed, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("auth: read challenge: %w", err)
	}
	challenge.MagicAuthID = magicID.String
	challenge.RadarAuthAttemptID = radarID.String
	challenge.OriginalIPAddress = payload.IPAddress
	challenge.OriginalUserAgent = payload.UserAgent
	challenge.ExpiresAt, err = parseTime(expires)
	if err != nil {
		return nil, err
	}
	challenge.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	if consumed.Valid {
		value, parseErr := parseTime(consumed.String)
		if parseErr != nil {
			return nil, parseErr
		}
		challenge.ConsumedAt = &value
	}
	if challenge.ConsumedAt != nil || !challenge.ExpiresAt.After(s.now()) {
		return nil, ErrInvalidCredentials
	}
	return &challenge, nil
}

func (s *ChallengeStore) Consume(ctx context.Context, id string) error {
	now := s.now().UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE auth_challenges SET consumed_at = ?
		WHERE id = ? AND consumed_at IS NULL AND expires_at > ?`,
		formatTime(now), id, formatTime(now))
	if err != nil {
		return fmt.Errorf("auth: consume challenge: %w", err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

func (s *ChallengeStore) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM auth_challenges WHERE expires_at < ?`, formatTime(before.UTC()))
	if err != nil {
		return 0, fmt.Errorf("auth: delete expired challenges: %w", err)
	}
	return result.RowsAffected()
}

func (s *ChallengeStore) createToken(ipAddress, userAgent string) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	payload, err := json.Marshal(challengeTokenPayload{
		Nonce:     base64.RawURLEncoding.EncodeToString(random),
		IPAddress: ipAddress, UserAgent: truncate(userAgent, 512),
	})
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := s.tokenMAC(encoded)
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

func (s *ChallengeStore) decodeToken(token string) (challengeTokenPayload, error) {
	var payload challengeTokenPayload
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return payload, ErrInvalidCredentials
	}
	providedMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(providedMAC, s.tokenMAC(parts[0])) {
		return payload, ErrInvalidCredentials
	}
	encoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(encoded, &payload) != nil || payload.Nonce == "" {
		return challengeTokenPayload{}, ErrInvalidCredentials
	}
	return payload, nil
}

func (s *ChallengeStore) tokenMAC(encoded string) []byte {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte("arca:magic-challenge-cookie:v1\x00"))
	_, _ = mac.Write([]byte(encoded))
	return mac.Sum(nil)
}

func (s *ChallengeStore) hashToken(token string) []byte {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte("arca:magic-challenge-store:v1\x00"))
	_, _ = mac.Write([]byte(token))
	return mac.Sum(nil)
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("auth: parse timestamp: %w", err)
	}
	return parsed, nil
}
