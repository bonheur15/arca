package api

import "embed"

// Files contains Arca's public API contract.
//
//go:embed openapi.yaml
var Files embed.FS
