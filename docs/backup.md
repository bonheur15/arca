# Backup and restore

Arca backups contain plaintext user files. Store them on encrypted, access-controlled media and test restores regularly.

## Create

Stop the Arca server, then run:

```sh
arca backup --data-dir /srv/arca --output /backups/arca-2026-08-14
```

Arca creates a consistent SQLite snapshot, enumerates exactly the immutable blobs referenced by that snapshot, verifies every SHA-256 digest while copying, writes a versioned manifest, syncs the tree, and publishes it atomically. Staging uploads, previews, WorkOS credentials, and cookie/HMAC secrets are excluded.

## Verify

```sh
arca restore --verify-only --source /backups/arca-2026-08-14
```

Verification checks the manifest, database and blob sizes/digests, SQLite `integrity_check`, `foreign_key_check`, and exact agreement between durable blob references and the manifest.

## Restore

The destination must be empty and the server must be offline:

```sh
arca restore \
  --source /backups/arca-2026-08-14 \
  --data-dir /srv/arca-restored
```

Restore verifies before copying and invalidates restored browser challenges, public sessions, revoked-session cache, idempotency records, and the WorkOS event cursor. Supply fresh WorkOS credentials through environment variables before first start. New local cookie/HMAC secrets invalidate old browser cookies. On startup Arca applies supported migrations and runs upload, storage, and quota reconciliation before readiness.

