# Arca operator runbook

## Deployment contract

Run one Arca process against one local filesystem. SQLite WAL files and blob storage must not live on NFS or a shared network volume. The process takes an exclusive lock at `locks/instance.lock` and refuses a second owner.

Each independently installed Arca instance needs its own WorkOS environment and credentials. The host needs outbound HTTPS access to WorkOS. A shared WorkOS environment shares the underlying identity directory, and an air-gapped deployment cannot use Magic Auth.

Recommended reverse-proxy shape:

1. Bind Arca to `127.0.0.1:8080`.
2. Terminate HTTPS at a maintained reverse proxy.
3. Configure Arca's public URL as the exact browser origin.
4. Add only the proxy network to trusted proxy CIDRs; forwarded IP headers from other peers are ignored.
5. Preserve streaming and byte-range responses and use transfer timeouts suitable for large files.

Alternatively, pass `--tls-cert` and `--tls-key`. Arca refuses a configured non-loopback HTTP public URL.

## Configuration precedence

Flags select the listener, data directory, and direct TLS files. Environment values override persisted settings:

```text
ARCA_LISTEN
ARCA_DATA_DIR
ARCA_TLS_CERT
ARCA_TLS_KEY
ARCA_PUBLIC_URL
ARCA_WORKOS_CLIENT_ID
ARCA_WORKOS_API_KEY
ARCA_COOKIE_KEY
ARCA_CODE_HMAC_KEY
ARCA_STATUS_HMAC_KEY
ARCA_FILESYSTEM_RESERVE_BYTES
```

Environment-injected secrets are used in memory and are not copied into `secrets.json`. Directories are mode `0700`; data and secret files are mode `0600`.

## Health and shutdown

- `GET /health/live` proves only that the HTTP process is alive.
- `GET /health/ready` checks initialization, SQLite, migrations, storage access, and the filesystem reserve.
- `arca doctor --data-dir /path/to/arca-data` performs an offline integrity and configuration check. Stop the server first because the data lock is exclusive.

Send SIGTERM or SIGINT for graceful shutdown. Arca stops accepting requests, allows up to 30 seconds for active handlers, cancels workers, checkpoints WAL, and keeps partial Tus uploads resumable.

## Recovery

With the server stopped and local filesystem access:

```sh
arca admin recovery-code --data-dir /srv/arca
arca admin add-superadmin --data-dir /srv/arca \
  --recovery-code 'ARCA-…' --username recovery-admin \
  --email recovery@example.com
```

Recovery codes are stored only as HMACs, expire after 15 minutes, work once, and are audited. Creating a new identity requires valid WorkOS credentials. The final active superadmin cannot be demoted, suspended, or deleted through ordinary administration.

## Incident checks

Check structured logs by request ID, `/admin/storage`, `/admin/jobs`, and `/admin/audit`. Never attach raw `secrets.json`, authorization headers, database files, or user blobs to a support ticket. Host administrators can read plaintext data; Arca does not claim zero knowledge or application-layer file encryption.

