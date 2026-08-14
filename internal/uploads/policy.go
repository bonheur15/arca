package uploads

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"arca/internal/database"
	"arca/internal/files"
)

func validateFilenamePolicy(ctx context.Context, queryer database.Queryer, ownerID, filename string) error {
	var encoded string
	if err := queryer.QueryRowContext(ctx, `SELECT blocked_extensions FROM user_policies WHERE user_id = ?`, ownerID).Scan(&encoded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return files.NewError(files.CodeInvalidState, "validate upload policy", ownerID, "owner policy is missing")
		}
		return err
	}
	var blocked []string
	if err := json.Unmarshal([]byte(encoded), &blocked); err != nil {
		return files.WrapError(files.CodeInvalidState, "validate upload policy", ownerID, err)
	}
	extension := ""
	if index := strings.LastIndex(filename, "."); index >= 0 && index < len(filename)-1 {
		extension = strings.ToLower(filename[index+1:])
	}
	for _, value := range blocked {
		candidate := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), ".")
		if candidate != "" && candidate == extension {
			return files.NewError(files.CodeFileTypeBlocked, "validate upload policy", ownerID, "the destination policy blocks this file extension")
		}
	}
	return nil
}

func validateMIMEPolicy(ctx context.Context, queryer database.Queryer, ownerID, mimeType string) error {
	var encoded string
	if err := queryer.QueryRowContext(ctx, `SELECT allowed_mime_groups FROM user_policies WHERE user_id = ?`, ownerID).Scan(&encoded); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return files.NewError(files.CodeInvalidState, "validate upload policy", ownerID, "owner policy is missing")
		}
		return err
	}
	var allowed []string
	if err := json.Unmarshal([]byte(encoded), &allowed); err != nil {
		return files.WrapError(files.CodeInvalidState, "validate upload policy", ownerID, err)
	}
	if len(allowed) == 0 {
		return nil
	}
	mimeType = strings.ToLower(strings.TrimSpace(strings.SplitN(mimeType, ";", 2)[0]))
	group, _, _ := strings.Cut(mimeType, "/")
	for _, value := range allowed {
		candidate := strings.ToLower(strings.TrimSpace(value))
		if !strings.Contains(candidate, "/") {
			candidate = strings.TrimSuffix(candidate, "s")
		}
		if candidate == mimeType || candidate == group || candidate == group+"/*" {
			return nil
		}
	}
	return files.NewError(files.CodeFileTypeBlocked, "validate upload policy", ownerID, "the destination policy does not allow this detected file type")
}
