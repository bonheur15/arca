package accounts

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// StatusTokenCodec creates opaque access-request status tokens. Only the HMAC
// is persisted, so a database reader cannot use it to query request status.
type StatusTokenCodec struct{ secret []byte }

func NewStatusTokenCodec(secret []byte) (*StatusTokenCodec, error) {
	if len(secret) < 32 {
		return nil, errors.New("accounts: status token secret must contain at least 32 bytes")
	}
	return &StatusTokenCodec{secret: append([]byte(nil), secret...)}, nil
}

func (c *StatusTokenCodec) Generate() (plaintext string, hash []byte, err error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", nil, err
	}
	plaintext = base64.RawURLEncoding.EncodeToString(random)
	return plaintext, c.Hash(plaintext), nil
}

func (c *StatusTokenCodec) Hash(plaintext string) []byte {
	mac := hmac.New(sha256.New, c.secret)
	_, _ = mac.Write([]byte("arca:access-request-status:v1\x00"))
	_, _ = mac.Write([]byte(plaintext))
	return mac.Sum(nil)
}
