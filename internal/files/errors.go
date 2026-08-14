package files

import (
	"errors"
	"fmt"
	"strings"
)

type ErrorCode string

const (
	CodeInvalid              ErrorCode = "invalid"
	CodeInvalidName          ErrorCode = "invalid_name"
	CodeNotFound             ErrorCode = "not_found"
	CodeForbidden            ErrorCode = "forbidden"
	CodeConflict             ErrorCode = "conflict"
	CodeRevisionMismatch     ErrorCode = "revision_mismatch"
	CodePreconditionRequired ErrorCode = "precondition_required"
	CodeCycle                ErrorCode = "folder_cycle"
	CodeItemLimit            ErrorCode = "item_limit_exceeded"
	CodeQuota                ErrorCode = "quota_exceeded"
	CodeDiskFull             ErrorCode = "disk_reserve_exceeded"
	CodeUploadLimit          ErrorCode = "upload_limit_exceeded"
	CodeOffsetMismatch       ErrorCode = "upload_offset_mismatch"
	CodeChecksumMismatch     ErrorCode = "checksum_mismatch"
	CodeFileTypeBlocked      ErrorCode = "file_type_blocked"
	CodeExpired              ErrorCode = "expired"
	CodeInvalidState         ErrorCode = "invalid_state"
	CodeCrossOwnerCopy       ErrorCode = "cross_owner_copy_requires_blob_copy"
)

// Error is safe to map to an RFC 9457 problem response. Cause remains internal.
type Error struct {
	Code     ErrorCode
	Op       string
	Resource string
	Detail   string
	Cause    error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	msg := string(e.Code)
	if e.Op != "" {
		msg = e.Op + ": " + msg
	}
	if e.Resource != "" {
		msg += " (" + e.Resource + ")"
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Cause }

func NewError(code ErrorCode, op, resource, detail string) error {
	return &Error{Code: code, Op: op, Resource: resource, Detail: detail}
}

func WrapError(code ErrorCode, op, resource string, cause error) error {
	return &Error{Code: code, Op: op, Resource: resource, Cause: cause}
}

func ErrorCodeOf(err error) ErrorCode {
	var domain *Error
	if errors.As(err, &domain) {
		return domain.Code
	}
	return ""
}

func mapConstraint(op, resource string, err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	if containsAny(message, "UNIQUE constraint failed", "constraint failed: UNIQUE") {
		return WrapError(CodeConflict, op, resource, err)
	}
	if containsAny(message, "FOREIGN KEY constraint failed", "constraint failed: FOREIGN KEY") {
		return WrapError(CodeInvalid, op, resource, err)
	}
	return fmt.Errorf("%s: %w", op, err)
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		// SQLite wraps constraint errors as plain strings; avoid coupling the
		// domain package to a concrete driver error type.
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}
