# Arca API guide

The source contract is available from a running instance at:

- `/api/openapi.yaml`
- `/api/openapi.json`
- `/api/docs`

Application endpoints live beneath `/api/v1`. Health endpoints are deliberately outside the versioned API.

## Authentication

The embedded browser application uses an HttpOnly sealed WorkOS session cookie plus Origin validation and an `X-CSRF-Token` header for mutations. External clients use personal access tokens:

```http
Authorization: Bearer arca_pat_…
```

PATs are shown once and stored as HMACs. They are never accepted in query strings. Available scopes are `files:read`, `files:write`, `shares:read`, `shares:write`, `tokens:manage`, and `admin:*`.

## Concurrency and retries

Resources return revision ETags. Lost-update-sensitive mutations require `If-Match`. Retryable create/action requests require a stable `Idempotency-Key`; Arca retains the response and request digest for 24 hours and rejects reuse with a different body.

Tus 1.0 uploads use `/api/v1/uploads` with creation, expiration, termination, and SHA-256 checksum extensions. Upload length must be known. The maximum PATCH chunk is 64 MiB. Browser defaults are three concurrent files and 8 MiB chunks.

## Errors and pagination

Errors are RFC 9457 `application/problem+json` documents containing `code`, `detail`, `request_id`, optional field errors, and optional retry timing. Lists default to 50 items, accept at most 200, and return opaque cursors.

Never infer authorization from a UUID. Arca rechecks the authenticated account, stable resource ID, live share ancestry, revocation, and expiry on every request.

