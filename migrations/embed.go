package migrations

import "embed"

// Files contains every immutable database migration shipped with Arca.
//
//go:embed *.sql
var Files embed.FS
