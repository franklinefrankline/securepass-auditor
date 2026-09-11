-- Password Strength Auditor Database Schema
-- Target Engine: PostgreSQL 15+

-- 1. Users Table for Authentication
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- 2. Audit Log Table
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
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

-- 3. Ensure user_id column exists if table existed previously
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name='audit_log' AND column_name='user_id'
    ) THEN
        ALTER TABLE audit_log ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE CASCADE;
    END IF;
END $$;

-- 4. Index to optimize querying latest audit records per user
CREATE INDEX IF NOT EXISTS idx_audit_log_user_checked ON audit_log (user_id, checked_at DESC);
