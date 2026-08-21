-- M25 reference schema. SQLiteGovernanceStore applies the equivalent schema
-- transactionally and records the immutable schema version in schema_meta.
CREATE TABLE schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE state_records (
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    revision INTEGER NOT NULL,
    payload TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (kind, key)
);

CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE idempotency_records (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    response_status INTEGER,
    response_json TEXT,
    created_at REAL NOT NULL,
    completed_at REAL,
    PRIMARY KEY (scope, key)
);

CREATE TABLE execution_claims (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    status TEXT NOT NULL,
    outcome_json TEXT,
    created_at REAL NOT NULL,
    completed_at REAL,
    PRIMARY KEY (scope, key),
    UNIQUE (claim_id)
);
