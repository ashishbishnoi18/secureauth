-- Add identities table for multi-provider authentication
-- Each user can have multiple identities (e.g., google, email magic link)

CREATE TABLE IF NOT EXISTS identities (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,           -- 'google', 'email'
    provider_subject TEXT NOT NULL,          -- google 'sub' or normalized email for email provider
    email           TEXT NOT NULL,           -- normalized email
    email_verified  BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Unique constraint: one identity per provider+subject combination
CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_provider_subject ON identities (provider, provider_subject);

-- Index for email lookups (linking by email)
CREATE INDEX IF NOT EXISTS idx_identities_email ON identities (email);

-- Index for user lookups
CREATE INDEX IF NOT EXISTS idx_identities_user_id ON identities (user_id);

-- Migrate existing users with google_sub to identities table
-- This preserves existing Google login users
INSERT INTO identities (user_id, provider, provider_subject, email, email_verified)
SELECT id, 'google', google_sub, LOWER(TRIM(email)), true
FROM users
WHERE google_sub IS NOT NULL AND google_sub != ''
ON CONFLICT (provider, provider_subject) DO NOTHING;

-- Make google_sub nullable for new users who only use email auth
-- First drop the unique constraint, then alter column
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_google_sub_key;
ALTER TABLE users ALTER COLUMN google_sub DROP NOT NULL;

-- Add index on email for users table (for quick lookups)
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- Magic links table for passwordless email authentication
CREATE TABLE IF NOT EXISTS magic_links (
    id                  BIGSERIAL PRIMARY KEY,
    email               TEXT NOT NULL,                  -- normalized email
    token_hash          TEXT NOT NULL UNIQUE,           -- HMAC-SHA256 hash of token
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    used_at             TIMESTAMPTZ,                    -- set when token is consumed
    request_ip          TEXT,                           -- IP that requested the link
    request_user_agent  TEXT,                           -- User agent that requested the link
    consumed_ip         TEXT,                           -- IP that consumed the link
    consumed_user_agent TEXT                            -- User agent that consumed the link
);

-- Index for token lookups
CREATE UNIQUE INDEX IF NOT EXISTS idx_magic_links_token_hash ON magic_links (token_hash);

-- Index for email lookups (rate limiting, cleanup)
CREATE INDEX IF NOT EXISTS idx_magic_links_email ON magic_links (email);

-- Index for expiry-based cleanup
CREATE INDEX IF NOT EXISTS idx_magic_links_expires_at ON magic_links (expires_at);
