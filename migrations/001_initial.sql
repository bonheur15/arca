CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE instance_settings (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    instance_id TEXT NOT NULL UNIQUE,
    initialized INTEGER NOT NULL DEFAULT 0 CHECK (initialized IN (0, 1)),
    name TEXT NOT NULL DEFAULT 'Arca',
    public_url TEXT NOT NULL DEFAULT '',
    filesystem_reserve_bytes INTEGER NOT NULL DEFAULT 1073741824 CHECK (filesystem_reserve_bytes >= 0),
    allow_access_requests INTEGER NOT NULL DEFAULT 1 CHECK (allow_access_requests IN (0, 1)),
    trusted_proxy_cidrs TEXT NOT NULL DEFAULT '[]',
    allowed_cors_origins TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    workos_user_id TEXT UNIQUE,
    username TEXT NOT NULL,
    username_key TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    email_key TEXT NOT NULL UNIQUE,
    display_name TEXT,
    role TEXT NOT NULL CHECK (role IN ('superadmin', 'member')),
    state TEXT NOT NULL CHECK (state IN ('provisioning', 'active', 'suspended', 'over_quota', 'deletion_pending', 'deleted')),
    quota_bytes INTEGER NOT NULL DEFAULT 0 CHECK (quota_bytes >= 0),
    quota_unlimited INTEGER NOT NULL DEFAULT 0 CHECK (quota_unlimited IN (0, 1)),
    used_bytes INTEGER NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    reserved_bytes INTEGER NOT NULL DEFAULT 0 CHECK (reserved_bytes >= 0),
    root_node_id TEXT,
    theme_mode TEXT NOT NULL DEFAULT 'system' CHECK (theme_mode IN ('system', 'light', 'dark')),
    accent TEXT NOT NULL DEFAULT 'green',
    density TEXT NOT NULL DEFAULT 'comfortable' CHECK (density IN ('compact', 'comfortable')),
    reduced_motion INTEGER NOT NULL DEFAULT 0 CHECK (reduced_motion IN (0, 1)),
    last_sign_in_at TEXT,
    deletion_due_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE user_policies (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    max_file_bytes INTEGER CHECK (max_file_bytes IS NULL OR max_file_bytes >= 0),
    max_items INTEGER NOT NULL DEFAULT 100000 CHECK (max_items > 0),
    allow_internal_sharing INTEGER NOT NULL DEFAULT 1 CHECK (allow_internal_sharing IN (0, 1)),
    allow_public_sharing INTEGER NOT NULL DEFAULT 1 CHECK (allow_public_sharing IN (0, 1)),
    allow_api_tokens INTEGER NOT NULL DEFAULT 1 CHECK (allow_api_tokens IN (0, 1)),
    max_concurrent_uploads INTEGER NOT NULL DEFAULT 3 CHECK (max_concurrent_uploads BETWEEN 1 AND 20),
    max_pending_uploads INTEGER NOT NULL DEFAULT 20 CHECK (max_pending_uploads BETWEEN 1 AND 100),
    max_active_public_shares INTEGER NOT NULL DEFAULT 10 CHECK (max_active_public_shares BETWEEN 0 AND 1000),
    max_public_ttl_minutes INTEGER NOT NULL DEFAULT 30 CHECK (max_public_ttl_minutes BETWEEN 1 AND 30),
    max_public_redemptions INTEGER NOT NULL DEFAULT 10 CHECK (max_public_redemptions BETWEEN 1 AND 10),
    allowed_mime_groups TEXT NOT NULL DEFAULT '[]',
    blocked_extensions TEXT NOT NULL DEFAULT '[]',
    upload_rate_bytes INTEGER,
    download_rate_bytes INTEGER,
    updated_at TEXT NOT NULL
);

CREATE TABLE access_requests (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    username_key TEXT NOT NULL,
    email TEXT NOT NULL,
    email_key TEXT NOT NULL,
    display_name TEXT,
    reason TEXT,
    state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'rejected')),
    status_token_hash BLOB NOT NULL,
    requester_ip_hash BLOB,
    requested_at TEXT NOT NULL,
    decided_at TEXT,
    decided_by TEXT REFERENCES users(id),
    decision_note TEXT,
    approved_user_id TEXT REFERENCES users(id)
);
CREATE UNIQUE INDEX access_requests_pending_email ON access_requests(email_key) WHERE state = 'pending';
CREATE UNIQUE INDEX access_requests_pending_username ON access_requests(username_key) WHERE state = 'pending';

CREATE TABLE blobs (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    storage_key TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('finalizing', 'ready', 'quarantined', 'deleting')),
    ref_count INTEGER NOT NULL DEFAULT 1 CHECK (ref_count >= 0),
    delete_after TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX blobs_owner_idx ON blobs(owner_id);
CREATE INDEX blobs_gc_idx ON blobs(state, delete_after);

CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    parent_id TEXT REFERENCES nodes(id),
    kind TEXT NOT NULL CHECK (kind IN ('folder', 'file')),
    name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    mime_type TEXT,
    size_bytes INTEGER NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    current_version_id TEXT,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by TEXT NOT NULL REFERENCES users(id),
    trashed_at TEXT,
    original_parent_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX nodes_active_sibling_name ON nodes(owner_id, parent_id, name_key) WHERE trashed_at IS NULL;
CREATE INDEX nodes_parent_idx ON nodes(parent_id, trashed_at, name_key);
CREATE INDEX nodes_owner_recent_idx ON nodes(owner_id, updated_at DESC);

CREATE TABLE file_versions (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    blob_id TEXT NOT NULL REFERENCES blobs(id),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    sha256 TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    UNIQUE(node_id, sequence)
);
CREATE INDEX file_versions_node_idx ON file_versions(node_id, sequence DESC);

CREATE TABLE uploads (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES users(id),
    owner_id TEXT NOT NULL REFERENCES users(id),
    parent_id TEXT NOT NULL REFERENCES nodes(id),
    name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    expected_bytes INTEGER NOT NULL CHECK (expected_bytes >= 0),
    committed_bytes INTEGER NOT NULL DEFAULT 0 CHECK (committed_bytes >= 0),
    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes >= 0),
    staging_key TEXT NOT NULL UNIQUE,
    intended_blob_key TEXT,
    conflict_mode TEXT NOT NULL CHECK (conflict_mode IN ('fail', 'keep_both', 'replace')),
    replace_node_id TEXT REFERENCES nodes(id),
	replace_revision INTEGER CHECK (replace_revision IS NULL OR replace_revision > 0),
    share_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('pending', 'finalizing', 'completed', 'cancelled', 'expired', 'failed')),
    error_code TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX uploads_owner_state_idx ON uploads(owner_id, state, expires_at);

CREATE TABLE shares (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    permission TEXT NOT NULL CHECK (permission IN ('viewer', 'editor')),
    allow_editor_uploads INTEGER NOT NULL DEFAULT 0 CHECK (allow_editor_uploads IN (0, 1)),
    editor_allowance_bytes INTEGER,
    editor_used_bytes INTEGER NOT NULL DEFAULT 0 CHECK (editor_used_bytes >= 0),
    expires_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE share_roots (
    share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    PRIMARY KEY (share_id, node_id)
);
CREATE TABLE share_recipients (
    share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id),
    PRIMARY KEY (share_id, user_id)
);
CREATE INDEX shares_owner_idx ON shares(owner_id, revoked_at, expires_at);
CREATE INDEX share_recipients_user_idx ON share_recipients(user_id, share_id);

CREATE TABLE public_shares (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    code_hash BLOB NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    redemption_limit INTEGER NOT NULL CHECK (redemption_limit BETWEEN 1 AND 10),
    redemption_count INTEGER NOT NULL DEFAULT 0 CHECK (redemption_count >= 0),
    revoked_at TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE public_share_roots (
    public_share_id TEXT NOT NULL REFERENCES public_shares(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    PRIMARY KEY (public_share_id, node_id)
);
CREATE TABLE public_access_sessions (
    id TEXT PRIMARY KEY,
    public_share_id TEXT NOT NULL REFERENCES public_shares(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL
);
CREATE INDEX public_shares_expiry_idx ON public_shares(expires_at, revoked_at);

CREATE TABLE favorites (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, node_id)
);

CREATE TABLE notifications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    read_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX notifications_user_idx ON notifications(user_id, read_at, created_at DESC);

CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_prefix TEXT NOT NULL UNIQUE,
    token_hash BLOB NOT NULL,
    scopes TEXT NOT NULL,
    expires_at TEXT,
    last_used_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE auth_challenges (
    id TEXT PRIMARY KEY,
    email_key TEXT NOT NULL,
    magic_auth_id TEXT,
    radar_attempt_id TEXT,
    token_hash BLOB NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX auth_challenges_expiry_idx ON auth_challenges(expires_at, consumed_at);

CREATE TABLE revoked_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    revoked_at TEXT NOT NULL
);

CREATE TABLE support_access (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES users(id),
    target_user_id TEXT NOT NULL REFERENCES users(id),
    reason TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE admin_recovery_codes (
    id TEXT PRIMARY KEY,
    code_hash BLOB NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX admin_recovery_expiry_idx ON admin_recovery_codes(expires_at, consumed_at);

CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'completed', 'failed', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 8 CHECK (max_attempts > 0),
    run_after TEXT NOT NULL,
    lease_until TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX jobs_ready_idx ON jobs(state, run_after, lease_until);

CREATE TABLE operation_leases (
    name TEXT PRIMARY KEY,
    lease_until TEXT NOT NULL,
    owner TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    actor_id TEXT REFERENCES users(id),
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    ip_address TEXT,
    user_agent TEXT,
    request_id TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX audit_events_created_idx ON audit_events(created_at DESC);
CREATE INDEX audit_events_actor_idx ON audit_events(actor_id, created_at DESC);

CREATE TABLE idempotency_keys (
    actor_key TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash BLOB NOT NULL,
    response_status INTEGER NOT NULL,
    response_headers TEXT NOT NULL DEFAULT '{}',
    response_body BLOB NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (actor_key, idempotency_key)
);

CREATE TABLE workos_event_cursor (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    cursor TEXT,
    last_polled_at TEXT,
    last_error TEXT
);
INSERT INTO workos_event_cursor(singleton) VALUES (1);

CREATE VIRTUAL TABLE node_search USING fts5(
    node_id UNINDEXED,
    owner_id UNINDEXED,
    name,
    mime_type,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER nodes_search_insert AFTER INSERT ON nodes WHEN new.trashed_at IS NULL BEGIN
    INSERT INTO node_search(node_id, owner_id, name, mime_type)
    VALUES (new.id, new.owner_id, new.name, COALESCE(new.mime_type, ''));
END;
CREATE TRIGGER nodes_search_update AFTER UPDATE OF name, mime_type, trashed_at ON nodes BEGIN
    DELETE FROM node_search WHERE node_id = old.id;
    INSERT INTO node_search(node_id, owner_id, name, mime_type)
    SELECT new.id, new.owner_id, new.name, COALESCE(new.mime_type, '')
    WHERE new.trashed_at IS NULL;
END;
CREATE TRIGGER nodes_search_delete AFTER DELETE ON nodes BEGIN
    DELETE FROM node_search WHERE node_id = old.id;
END;
