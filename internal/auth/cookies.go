package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	ProductionSessionCookieName   = "__Host-arca_session"
	ProductionChallengeCookieName = "__Host-arca_challenge"
	ProductionCSRFCookieName      = "__Host-arca_csrf"
)

type CookiePolicy struct {
	Secure   bool
	SameSite http.SameSite
}

func DefaultCookiePolicy(secure bool) CookiePolicy {
	return CookiePolicy{Secure: secure, SameSite: http.SameSiteLaxMode}
}

func (p CookiePolicy) SessionName() string {
	if p.Secure {
		return ProductionSessionCookieName
	}
	return "arca_session"
}

func (p CookiePolicy) ChallengeName() string {
	if p.Secure {
		return ProductionChallengeCookieName
	}
	return "arca_challenge"
}

func (p CookiePolicy) CSRFName() string {
	if p.Secure {
		return ProductionCSRFCookieName
	}
	return "arca_csrf"
}

func (p CookiePolicy) SetChallenge(w http.ResponseWriter, value string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: p.ChallengeName(), Value: value, Path: "/", Expires: expiresAt.UTC(),
		MaxAge: maxAge(expiresAt), HttpOnly: true, Secure: p.Secure, SameSite: normalizedSameSite(p.SameSite),
	})
}

func (p CookiePolicy) SetSession(w http.ResponseWriter, value string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: p.SessionName(), Value: value, Path: "/", Expires: expiresAt.UTC(),
		MaxAge: maxAge(expiresAt), HttpOnly: true, Secure: p.Secure, SameSite: normalizedSameSite(p.SameSite),
	})
}

// SetCSRF deliberately leaves HttpOnly false: the React client reads the
// double-submit value and echoes it in an X-CSRF-Token header.
func (p CookiePolicy) SetCSRF(w http.ResponseWriter, value string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: p.CSRFName(), Value: value, Path: "/", Expires: expiresAt.UTC(),
		MaxAge: maxAge(expiresAt), HttpOnly: false, Secure: p.Secure, SameSite: normalizedSameSite(p.SameSite),
	})
}

func (p CookiePolicy) ClearAuth(w http.ResponseWriter) {
	for _, name := range []string{p.SessionName(), p.ChallengeName(), p.CSRFName()} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0),
			HttpOnly: name != p.CSRFName(), Secure: p.Secure, SameSite: normalizedSameSite(p.SameSite),
		})
	}
}

func ReadCookie(request *http.Request, name string) (string, error) {
	cookie, err := request.Cookie(name)
	if err != nil || cookie.Value == "" {
		return "", ErrUnauthenticated
	}
	return cookie.Value, nil
}

func GenerateCSRFToken(secret []byte, sessionID string) (string, error) {
	if len(secret) < 32 || sessionID == "" {
		return "", errors.New("auth: csrf secret and session id are required")
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(nonce)
	mac := csrfMAC(secret, sessionID, encoded)
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

func ValidateCSRFToken(secret []byte, sessionID, cookieValue, headerValue string) error {
	if len(secret) < 32 || sessionID == "" || cookieValue == "" || headerValue == "" ||
		!hmac.Equal([]byte(cookieValue), []byte(headerValue)) {
		return ErrInvalidCSRF
	}
	parts := strings.Split(cookieValue, ".")
	if len(parts) != 2 {
		return ErrInvalidCSRF
	}
	provided, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(provided, csrfMAC(secret, sessionID, parts[0])) {
		return ErrInvalidCSRF
	}
	return nil
}

func csrfMAC(secret []byte, sessionID, nonce string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte("arca:csrf:v1\x00"))
	_, _ = mac.Write([]byte(sessionID))
	_, _ = mac.Write([]byte{'\x00'})
	_, _ = mac.Write([]byte(nonce))
	return mac.Sum(nil)
}

func normalizedSameSite(value http.SameSite) http.SameSite {
	if value == 0 {
		return http.SameSiteLaxMode
	}
	return value
}

func maxAge(expiresAt time.Time) int {
	seconds := int(time.Until(expiresAt).Seconds())
	if seconds < 1 {
		return 1
	}
	return seconds
}
