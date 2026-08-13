package accounts

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

var fold = cases.Fold()

// NormalizeUsername returns a display-preserving NFC username and a
// case-folded uniqueness key.
func NormalizeUsername(raw string) (value, key string, err error) {
	value = norm.NFC.String(strings.TrimSpace(raw))
	length := utf8.RuneCountInString(value)
	if length < 3 || length > 64 {
		return "", "", fmt.Errorf("%w: username must contain 3 to 64 characters", ErrInvalidInput)
	}
	for i, r := range value {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' || r == '-' || r == '.' {
			if (i == 0 || i+utf8.RuneLen(r) == len(value)) && (r == '_' || r == '-' || r == '.') {
				return "", "", fmt.Errorf("%w: username cannot start or end with punctuation", ErrInvalidInput)
			}
			continue
		}
		return "", "", fmt.Errorf("%w: username contains an unsupported character", ErrInvalidInput)
	}
	key = fold.String(value)
	return value, key, nil
}

// NormalizeEmail validates a bare mailbox and returns its NFC representation
// plus a case-folded lookup key. Arca intentionally treats the complete email
// address case-insensitively for account uniqueness and login lookup.
func NormalizeEmail(raw string) (value, key string, err error) {
	value = norm.NFC.String(strings.TrimSpace(raw))
	if value == "" || len(value) > 254 || strings.ContainsAny(value, "\r\n\t") {
		return "", "", fmt.Errorf("%w: invalid email", ErrInvalidInput)
	}
	parsed, parseErr := mail.ParseAddress(value)
	if parseErr != nil || parsed.Name != "" || parsed.Address != value {
		return "", "", fmt.Errorf("%w: invalid email", ErrInvalidInput)
	}
	parts := strings.Split(value, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || !strings.Contains(parts[1], ".") {
		return "", "", fmt.Errorf("%w: invalid email", ErrInvalidInput)
	}
	key = fold.String(value)
	return value, key, nil
}

func NormalizeDisplayName(raw string) (string, error) {
	value := norm.NFC.String(strings.TrimSpace(raw))
	if utf8.RuneCountInString(value) > 100 {
		return "", fmt.Errorf("%w: display name is too long", ErrInvalidInput)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("%w: display name contains a control character", ErrInvalidInput)
		}
	}
	return value, nil
}

func ValidatePreferences(preferences Preferences) error {
	if preferences.ThemeMode != ThemeSystem && preferences.ThemeMode != ThemeLight && preferences.ThemeMode != ThemeDark {
		return fmt.Errorf("%w: unsupported theme mode", ErrInvalidInput)
	}
	if _, ok := AllowedAccents[preferences.Accent]; !ok {
		return fmt.Errorf("%w: unsupported accent", ErrInvalidInput)
	}
	if preferences.Density != DensityCompact && preferences.Density != DensityComfortable {
		return fmt.Errorf("%w: unsupported density", ErrInvalidInput)
	}
	return nil
}

func ValidatePolicy(policy Policy) error {
	if policy.MaxFileBytes != nil && *policy.MaxFileBytes < 0 {
		return fmt.Errorf("%w: max file size must not be negative", ErrInvalidInput)
	}
	if policy.MaxItems <= 0 || policy.MaxConcurrentUploads < 1 || policy.MaxConcurrentUploads > 20 ||
		policy.MaxPendingUploads < 1 || policy.MaxPendingUploads > 100 ||
		policy.MaxActivePublicShares < 0 || policy.MaxActivePublicShares > 1000 ||
		policy.MaxPublicTTLMinutes < 1 || policy.MaxPublicTTLMinutes > 30 ||
		policy.MaxPublicRedemptions < 1 || policy.MaxPublicRedemptions > 10 {
		return fmt.Errorf("%w: policy value is outside its supported range", ErrInvalidInput)
	}
	if (policy.UploadRateBytes != nil && *policy.UploadRateBytes < 0) ||
		(policy.DownloadRateBytes != nil && *policy.DownloadRateBytes < 0) {
		return fmt.Errorf("%w: rate limits must not be negative", ErrInvalidInput)
	}
	return nil
}
