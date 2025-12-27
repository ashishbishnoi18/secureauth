-- Enforce uniqueness of verified emails across all identities
-- This ensures deterministic account linking: same verified email = same user
-- Unverified emails are allowed to have duplicates (e.g., pending verification)

CREATE UNIQUE INDEX IF NOT EXISTS idx_identities_verified_email
    ON identities (email)
    WHERE email_verified = true;
