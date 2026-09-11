-- Password Strength Auditor Database Schema
-- Target Engine: PostgreSQL 15+

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    password_hash VARCHAR(64) NOT NULL,
    score SMALLINT NOT NULL,
    length SMALLINT NOT NULL,
    has_upper BOOLEAN NOT NULL,
    has_lower BOOLEAN NOT NULL,
    has_digit BOOLEAN NOT NULL,
    has_symbol BOOLEAN NOT NULL,
    is_common BOOLEAN NOT NULL,
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index to optimize querying latest audit records
CREATE INDEX IF NOT EXISTS idx_audit_log_checked_at ON audit_log (checked_at DESC);
