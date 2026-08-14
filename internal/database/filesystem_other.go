//go:build !linux

package database

// Linux is Arca v1's supported production target. Other platforms retain the
// SQLite safety gates but cannot use the Linux filesystem-type check.
func validateLocalFilesystem(string) error { return nil }
