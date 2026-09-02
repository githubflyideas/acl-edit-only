// Package db provides SQLite WAL storage for aclweb.
// Only aclweb accesses the database; acl-agent is stateless and DB-free.
package db

import (
	"database/sql"
	"fmt"

	_ "github.com/glebarez/sqlite"
)

// Open opens (or creates) the SQLite database at path, enables WAL mode,
// and runs all migrations.
func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite WAL is fine with concurrent readers but single writer
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(schema)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,           -- bcrypt
    role          TEXT    NOT NULL CHECK(role IN ('admin','approver','operator','viewer')),
    active        INTEGER NOT NULL DEFAULT 1,
    last_login_at INTEGER,                    -- unix seconds
    created_at    INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT    PRIMARY KEY,           -- random 32-byte hex
    user_id    INTEGER NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
    key        TEXT    PRIMARY KEY,           -- "user:<name>" or "ip:<addr>"
    count      INTEGER NOT NULL DEFAULT 0,
    window_end INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS change_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    request_code    TEXT    NOT NULL UNIQUE, -- REQ-YYYYMMDD-NNN
    action          TEXT    NOT NULL CHECK(action IN ('add_rule','delete_rule')),
    requester_id    INTEGER NOT NULL REFERENCES users(id),
    approver_id     INTEGER REFERENCES users(id),
    state           TEXT    NOT NULL DEFAULT 'pending'
                            CHECK(state IN ('pending','approved','rejected','dispatching',
                                            'active','dispatch_failed','dead_letter',
                                            'drift','inconsistent','revoking','revoked',
                                            'revoke_failed','expired')),
    reason          TEXT    NOT NULL,         -- application text; never enters command
    approve_comment TEXT,
    protocol        TEXT,
    src_ip          TEXT,
    src_wildcard    TEXT,
    src_port_op     TEXT,
    src_port_val    INTEGER,
    src_port_low    INTEGER,
    src_port_high   INTEGER,
    dst_ip          TEXT    NOT NULL,
    dst_wildcard    TEXT    NOT NULL DEFAULT '0',
    dst_port_op     TEXT,
    dst_port_val    INTEGER,
    dst_port_low    INTEGER,
    dst_port_high   INTEGER,
    rule_id         INTEGER,                  -- assigned after snapshot
    shadow_ok       INTEGER NOT NULL DEFAULT 0, -- explicit approver ack of partial shadow
    shadow_by       INTEGER REFERENCES users(id),
    submitted_at    INTEGER NOT NULL DEFAULT (unixepoch()),
    approved_at     INTEGER,
    dispatched_at   INTEGER,
    expires_at      INTEGER
);

CREATE TABLE IF NOT EXISTS dispatches (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id       INTEGER NOT NULL REFERENCES change_requests(id),
    idempotency_key  TEXT    NOT NULL UNIQUE,  -- request_code + attempt hash
    state            TEXT    NOT NULL DEFAULT 'pending'
                             CHECK(state IN ('pending','running','done','failed')),
    attempts         INTEGER NOT NULL DEFAULT 0,
    next_attempt_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    last_error       TEXT,
    created_at       INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS acl_snapshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    acl_num      INTEGER NOT NULL,
    raw_text     TEXT    NOT NULL,  -- verbatim device output
    fingerprint  TEXT    NOT NULL,  -- sha256 of normalised rule set
    rule_count   INTEGER NOT NULL,
    trigger      TEXT    NOT NULL CHECK(trigger IN ('pre_request','pre_dispatch','post_dispatch','reconcile','startup')),
    captured_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS change_artifacts (
    request_id      INTEGER PRIMARY KEY REFERENCES change_requests(id),
    snapshot_before_id INTEGER REFERENCES acl_snapshots(id),
    old_config      TEXT    NOT NULL,  -- S1 raw text
    new_config      TEXT    NOT NULL,  -- E predicted text
    diff_text       TEXT    NOT NULL,  -- D unified diff
    plan_json       TEXT    NOT NULL,  -- P typed JSON
    old_sha256      TEXT    NOT NULL,
    new_sha256      TEXT    NOT NULL,
    diff_sha256     TEXT    NOT NULL,
    plan_sha256     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id       INTEGER NOT NULL REFERENCES change_requests(id),
    plan_sha256      TEXT    NOT NULL,
    op               TEXT    NOT NULL,
    result           TEXT    NOT NULL,
    stage            TEXT,
    detail           TEXT,
    raw_output       TEXT,            -- device output (auth phase excluded)
    snapshot_before  INTEGER REFERENCES acl_snapshots(id),
    snapshot_after   INTEGER REFERENCES acl_snapshots(id),
    bound_acl        INTEGER,
    bound_range_min  INTEGER,
    bound_range_max  INTEGER,
    bound_alloc_max  INTEGER,
    config_sha256    TEXT,
    agent_version    TEXT,
    started_at       INTEGER NOT NULL DEFAULT (unixepoch()),
    finished_at      INTEGER
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id    INTEGER REFERENCES users(id),
    actor_label TEXT    NOT NULL,   -- username at time of action
    entity_type TEXT    NOT NULL,   -- e.g. "change_request", "user"
    entity_id   INTEGER,
    event       TEXT    NOT NULL,   -- e.g. "submitted", "approved", "self_approval_denied"
    detail      TEXT    NOT NULL DEFAULT '{}',  -- JSON, never free text
    occurred_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_cr_state         ON change_requests(state);
CREATE INDEX IF NOT EXISTS idx_cr_requester     ON change_requests(requester_id);
CREATE INDEX IF NOT EXISTS idx_dispatches_next  ON dispatches(next_attempt_at) WHERE state='pending';
CREATE INDEX IF NOT EXISTS idx_audit_entity     ON audit_logs(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor      ON audit_logs(actor_id);
`
