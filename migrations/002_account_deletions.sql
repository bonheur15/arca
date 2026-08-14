CREATE TABLE account_deletions (
    user_id TEXT PRIMARY KEY REFERENCES users(id),
    mode TEXT NOT NULL CHECK (mode IN ('transfer', 'purge')),
    transfer_to_user_id TEXT REFERENCES users(id),
    state TEXT NOT NULL CHECK (state IN ('scheduled', 'local_complete', 'completed', 'cancelled')),
    workos_user_id TEXT,
    job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id),
    created_by TEXT NOT NULL,
    due_at TEXT NOT NULL,
    local_completed_at TEXT,
    workos_completed_at TEXT,
    local_audited_at TEXT,
    completed_audited_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (mode = 'transfer' AND transfer_to_user_id IS NOT NULL AND transfer_to_user_id <> user_id)
        OR (mode = 'purge' AND transfer_to_user_id IS NULL)
    )
);

CREATE INDEX account_deletions_state_due_idx ON account_deletions(state, due_at);
