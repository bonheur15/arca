# Arca

Arca is a fast, single-node file vault for private organizations. One Linux binary serves the React application and a versioned REST API, stores metadata in SQLite, and streams immutable files from local disk.

The current v1 implementation includes:

- WorkOS Magic Auth with Arca-owned roles, states, policies, quotas, and CSRF-protected sealed sessions.
- First-run setup with a console-only 20-character code and verified initial superadmin.
- Folders, search, favorites, recent files, trash, immutable version history, safe previews, ranges, copies, and crash-safe Tus uploads.
- Internal viewer/editor bundles and short-lived five-digit public exchanges with hashed codes and redemption limits.
- Personal access tokens, OpenAPI documentation, SSE notifications, auditing, durable jobs, diagnostics, backup/restore, and terminal recovery.
- A responsive React 19 interface with keyboard workflows, accessible primitives, themes, density, and reduced-motion support.

## Build

Requirements are Go 1.25+, Node.js, and pnpm 10.33.0.

```sh
make install-web
make check
make build VERSION=0.1.0
./bin/arca-linux-amd64 version
```

The release binary has no Node, C toolchain, or external web-asset dependency.

## Run

```sh
./bin/arca-linux-amd64 serve \
  --listen 127.0.0.1:8080 \
  --data-dir ./arca-data
```

On an empty data directory Arca prints a one-use setup code to the terminal. Open `/setup`, enter that code, then configure a unique WorkOS environment and the first superadmin. Magic Auth and WorkOS reconciliation require outbound HTTPS; Arca is not an air-gapped product.

For remote access, use an HTTPS reverse proxy and set the public URL to its exact origin, or pass `--tls-cert` and `--tls-key` directly.

## Documentation

- [Operator runbook](docs/operator-runbook.md)
- [Backup and restore](docs/backup.md)
- [API guide](docs/api.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

No license has been selected yet. Copyright and redistribution rights are therefore not granted by this repository.

