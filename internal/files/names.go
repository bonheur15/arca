package files

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const MaxNameRunes = 255

var fold = cases.Fold()

// NormalizeName NFC-normalizes a display name and derives its case-folded
// sibling uniqueness key. It never silently trims user-visible characters.
func NormalizeName(input string) (display, key string, err error) {
	if !utf8.ValidString(input) {
		return "", "", NewError(CodeInvalidName, "normalize name", "", "name is not valid UTF-8")
	}
	display = norm.NFC.String(input)
	if display == "" || strings.TrimSpace(display) == "" {
		return "", "", NewError(CodeInvalidName, "normalize name", "", "name cannot be empty")
	}
	if display == "." || display == ".." {
		return "", "", NewError(CodeInvalidName, "normalize name", "", "reserved path name")
	}
	if utf8.RuneCountInString(display) > MaxNameRunes {
		return "", "", NewError(CodeInvalidName, "normalize name", "", fmt.Sprintf("name exceeds %d Unicode characters", MaxNameRunes))
	}
	for _, r := range display {
		if r == '/' || r == 0 || unicode.IsControl(r) {
			return "", "", NewError(CodeInvalidName, "normalize name", "", "name contains a path separator or control character")
		}
	}
	return display, fold.String(display), nil
}

func nextAvailableName(name string, occupied func(key string) (bool, error)) (string, string, error) {
	display, key, err := NormalizeName(name)
	if err != nil {
		return "", "", err
	}
	exists, err := occupied(key)
	if err != nil || !exists {
		return display, key, err
	}
	stem, extension := splitExtension(display)
	for i := 1; i <= 10_000; i++ {
		candidate := fmt.Sprintf("%s (%d)%s", stem, i, extension)
		candidate, candidateKey, err := NormalizeName(candidate)
		if err != nil {
			return "", "", err
		}
		exists, err := occupied(candidateKey)
		if err != nil {
			return "", "", err
		}
		if !exists {
			return candidate, candidateKey, nil
		}
	}
	return "", "", NewError(CodeConflict, "choose available name", "", "too many sibling name conflicts")
}

func splitExtension(name string) (string, string) {
	index := strings.LastIndex(name, ".")
	if index <= 0 || index == len(name)-1 {
		return name, ""
	}
	return name[:index], name[index:]
}
