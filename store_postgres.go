package secureauth

import (
    "context"
    "crypto/sha256"
    "database/sql"
    "embed"
    "encoding/base64"
    "errors"
    "fmt"
    "strings"
    "time"
)

// ErrDuplicateVerifiedEmail is returned when trying to create an identity
// with a verified email that already belongs to another user.
// This is a security-sensitive error: callers must not expose details to users.
var ErrDuplicateVerifiedEmail = errors.New("verified email already exists")

//go:embed migrations/*.sql
var migrationsFS embed.FS

type PostgresStore struct {
    db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
    return &PostgresStore{db: db}
}

// ============================================================================
// User Methods
// ============================================================================

func (s *PostgresStore) GetUserByGoogleSub(ctx context.Context, sub string) (*User, error) {
    row := s.db.QueryRowContext(ctx, `
        SELECT id, google_sub, email, name, avatar_url, created_at, updated_at
        FROM users
        WHERE google_sub = $1
    `, sub)

    u := &User{}
    var googleSub sql.NullString
    if err := row.Scan(&u.ID, &googleSub, &u.Email, &u.Name, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt); err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, err
    }
    u.GoogleSub = googleSub.String
    return u, nil
}

func (s *PostgresStore) GetUserByID(ctx context.Context, id int64) (*User, error) {
    row := s.db.QueryRowContext(ctx, `
        SELECT id, google_sub, email, name, avatar_url, created_at, updated_at
        FROM users
        WHERE id = $1
    `, id)

    u := &User{}
    var googleSub sql.NullString
    if err := row.Scan(&u.ID, &googleSub, &u.Email, &u.Name, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt); err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, err
    }
    u.GoogleSub = googleSub.String
    return u, nil
}

func (s *PostgresStore) CreateUser(ctx context.Context, u *User) error {
    var googleSub sql.NullString
    if u.GoogleSub != "" {
        googleSub = sql.NullString{String: u.GoogleSub, Valid: true}
    }
    return s.db.QueryRowContext(ctx, `
        INSERT INTO users (google_sub, email, name, avatar_url)
        VALUES ($1, $2, $3, $4)
        RETURNING id, created_at, updated_at
    `, googleSub, u.Email, u.Name, u.AvatarURL).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
}

func (s *PostgresStore) CreateUserMinimal(ctx context.Context, email, name string) (*User, error) {
    // Defensive email normalization
    normalizedEmail := strings.TrimSpace(strings.ToLower(email))
    u := &User{
        Email: normalizedEmail,
        Name:  name,
    }
    err := s.db.QueryRowContext(ctx, `
        INSERT INTO users (google_sub, email, name, avatar_url)
        VALUES (NULL, $1, $2, '')
        RETURNING id, created_at, updated_at
    `, normalizedEmail, name).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
    if err != nil {
        return nil, err
    }
    return u, nil
}

func (s *PostgresStore) UpdateUser(ctx context.Context, u *User) error {
    return s.db.QueryRowContext(ctx, `
        UPDATE users
        SET email = $1,
            name = $2,
            avatar_url = $3,
            updated_at = now()
        WHERE id = $4
        RETURNING updated_at
    `, u.Email, u.Name, u.AvatarURL, u.ID).Scan(&u.UpdatedAt)
}

// ============================================================================
// Session Methods
// ============================================================================

func (s *PostgresStore) CreateSession(ctx context.Context, sess *Session) error {
    hash := hashSessionToken(sess.SessionToken)
    return s.db.QueryRowContext(ctx, `
        INSERT INTO sessions (session_token_hash, user_id, expires_at, last_seen_at, user_agent, ip_address)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, created_at, last_seen_at
    `, hash, sess.UserID, sess.ExpiresAt, sess.LastSeenAt, sess.UserAgent, sess.IPAddress).
        Scan(&sess.ID, &sess.CreatedAt, &sess.LastSeenAt)
}

func (s *PostgresStore) GetSessionByToken(ctx context.Context, token string) (*Session, *User, error) {
    hash := hashSessionToken(token)

    row := s.db.QueryRowContext(ctx, `
        SELECT
            s.id, s.user_id, s.created_at, s.expires_at, s.last_seen_at, s.user_agent, s.ip_address,
            u.id, u.google_sub, u.email, u.name, u.avatar_url, u.created_at, u.updated_at
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.session_token_hash = $1
    `, hash)

    sess := &Session{SessionToken: token}
    user := &User{}
    var googleSub sql.NullString
    if err := row.Scan(
        &sess.ID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt, &sess.LastSeenAt, &sess.UserAgent, &sess.IPAddress,
        &user.ID, &googleSub, &user.Email, &user.Name, &user.AvatarURL, &user.CreatedAt, &user.UpdatedAt,
    ); err != nil {
        if err == sql.ErrNoRows {
            return nil, nil, nil
        }
        return nil, nil, err
    }
    user.GoogleSub = googleSub.String

    return sess, user, nil
}

func (s *PostgresStore) TouchSession(ctx context.Context, id int64, newExpiresAt time.Time) error {
    _, err := s.db.ExecContext(ctx, `
        UPDATE sessions
        SET last_seen_at = now(),
            expires_at = $1
        WHERE id = $2
    `, newExpiresAt, id)
    return err
}

func (s *PostgresStore) DeleteSessionByToken(ctx context.Context, token string) error {
    hash := hashSessionToken(token)
    _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE session_token_hash = $1`, hash)
    return err
}

// ============================================================================
// Identity Methods
// ============================================================================

func (s *PostgresStore) GetIdentityByProviderSubject(ctx context.Context, provider, subject string) (*Identity, error) {
    row := s.db.QueryRowContext(ctx, `
        SELECT id, user_id, provider, provider_subject, email, email_verified, created_at, updated_at
        FROM identities
        WHERE provider = $1 AND provider_subject = $2
    `, provider, subject)

    i := &Identity{}
    if err := row.Scan(&i.ID, &i.UserID, &i.Provider, &i.ProviderSubject, &i.Email, &i.EmailVerified, &i.CreatedAt, &i.UpdatedAt); err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, err
    }
    return i, nil
}

func (s *PostgresStore) GetIdentitiesByEmail(ctx context.Context, email string) ([]*Identity, error) {
    rows, err := s.db.QueryContext(ctx, `
        SELECT id, user_id, provider, provider_subject, email, email_verified, created_at, updated_at
        FROM identities
        WHERE email = $1 AND email_verified = true
        ORDER BY created_at ASC
    `, email)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var identities []*Identity
    for rows.Next() {
        i := &Identity{}
        if err := rows.Scan(&i.ID, &i.UserID, &i.Provider, &i.ProviderSubject, &i.Email, &i.EmailVerified, &i.CreatedAt, &i.UpdatedAt); err != nil {
            return nil, err
        }
        identities = append(identities, i)
    }
    return identities, rows.Err()
}

func (s *PostgresStore) CreateIdentity(ctx context.Context, i *Identity) error {
    // Defensive email normalization
    i.Email = strings.TrimSpace(strings.ToLower(i.Email))
    i.ProviderSubject = strings.TrimSpace(i.ProviderSubject)
    if i.Provider == "email" {
        i.ProviderSubject = strings.ToLower(i.ProviderSubject)
    }

    err := s.db.QueryRowContext(ctx, `
        INSERT INTO identities (user_id, provider, provider_subject, email, email_verified)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, created_at, updated_at
    `, i.UserID, i.Provider, i.ProviderSubject, i.Email, i.EmailVerified).Scan(&i.ID, &i.CreatedAt, &i.UpdatedAt)

    if err != nil && isUniqueViolation(err, "idx_identities_verified_email") {
        return ErrDuplicateVerifiedEmail
    }
    return err
}

func (s *PostgresStore) UpdateIdentity(ctx context.Context, i *Identity) error {
    return s.db.QueryRowContext(ctx, `
        UPDATE identities
        SET email = $1,
            email_verified = $2,
            updated_at = now()
        WHERE id = $3
        RETURNING updated_at
    `, i.Email, i.EmailVerified, i.ID).Scan(&i.UpdatedAt)
}

// ============================================================================
// Magic Link Methods
// ============================================================================

func (s *PostgresStore) CreateMagicLink(ctx context.Context, m *MagicLink) error {
    // Defensive email normalization
    m.Email = strings.TrimSpace(strings.ToLower(m.Email))
    return s.db.QueryRowContext(ctx, `
        INSERT INTO magic_links (email, token_hash, expires_at, request_ip, request_user_agent)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, created_at
    `, m.Email, m.TokenHash, m.ExpiresAt, m.RequestIP, m.RequestUserAgent).Scan(&m.ID, &m.CreatedAt)
}

func (s *PostgresStore) GetMagicLinkByTokenHash(ctx context.Context, tokenHash string) (*MagicLink, error) {
    row := s.db.QueryRowContext(ctx, `
        SELECT id, email, token_hash, created_at, expires_at, used_at, request_ip, request_user_agent, consumed_ip, consumed_user_agent
        FROM magic_links
        WHERE token_hash = $1
    `, tokenHash)

    m := &MagicLink{}
    var usedAt sql.NullTime
    var requestIP, requestUserAgent, consumedIP, consumedUserAgent sql.NullString
    if err := row.Scan(&m.ID, &m.Email, &m.TokenHash, &m.CreatedAt, &m.ExpiresAt, &usedAt, &requestIP, &requestUserAgent, &consumedIP, &consumedUserAgent); err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, err
    }
    if usedAt.Valid {
        m.UsedAt = &usedAt.Time
    }
    m.RequestIP = requestIP.String
    m.RequestUserAgent = requestUserAgent.String
    m.ConsumedIP = consumedIP.String
    m.ConsumedUserAgent = consumedUserAgent.String
    return m, nil
}

func (s *PostgresStore) ConsumeMagicLink(ctx context.Context, id int64, consumedIP, consumedUserAgent string) error {
    result, err := s.db.ExecContext(ctx, `
        UPDATE magic_links
        SET used_at = now(),
            consumed_ip = $1,
            consumed_user_agent = $2
        WHERE id = $3 AND used_at IS NULL
    `, consumedIP, consumedUserAgent, id)
    if err != nil {
        return err
    }
    rowsAffected, err := result.RowsAffected()
    if err != nil {
        return err
    }
    if rowsAffected == 0 {
        return fmt.Errorf("magic link already used or not found")
    }
    return nil
}

func (s *PostgresStore) CountRecentMagicLinks(ctx context.Context, email string, since time.Time) (int, error) {
    var count int
    err := s.db.QueryRowContext(ctx, `
        SELECT COUNT(*)
        FROM magic_links
        WHERE email = $1 AND created_at > $2
    `, email, since).Scan(&count)
    return count, err
}

func (s *PostgresStore) DeleteExpiredMagicLinks(ctx context.Context) error {
    _, err := s.db.ExecContext(ctx, `
        DELETE FROM magic_links
        WHERE expires_at < now() OR used_at IS NOT NULL
    `)
    return err
}

// ============================================================================
// Utility Functions
// ============================================================================

// hashSessionToken hashes the session token so we don't store it in plaintext in the DB.
func hashSessionToken(token string) string {
    sum := sha256.Sum256([]byte(token))
    return base64.RawURLEncoding.EncodeToString(sum[:])
}

// isUniqueViolation checks if the error is a Postgres unique constraint violation
// for the specified index name. Uses string matching since we don't want to import
// the pq driver directly (users might use pgx or other drivers).
func isUniqueViolation(err error, indexName string) bool {
    if err == nil {
        return false
    }
    errStr := err.Error()
    // Postgres unique violation error code is 23505
    // The error message typically contains the constraint/index name
    return strings.Contains(errStr, "23505") ||
        (strings.Contains(errStr, "duplicate key") && strings.Contains(errStr, indexName)) ||
        (strings.Contains(errStr, "unique constraint") && strings.Contains(errStr, indexName))
}

// Migrate applies the embedded migrations for the auth schema, with per-file transactions.
func Migrate(ctx context.Context, db *sql.DB) error {
    if _, err := db.ExecContext(ctx, `
        CREATE TABLE IF NOT EXISTS schema_migrations_auth (
            version TEXT PRIMARY KEY
        );
    `); err != nil {
        return fmt.Errorf("create schema_migrations_auth: %w", err)
    }

    entries, err := migrationsFS.ReadDir("migrations")
    if err != nil {
        return fmt.Errorf("read migrations dir: %w", err)
    }

    for _, e := range entries {
        name := e.Name()
        if e.IsDir() {
            continue
        }

        tx, err := db.BeginTx(ctx, nil)
        if err != nil {
            return fmt.Errorf("begin tx for %s: %w", name, err)
        }

        var exists bool
        if err := tx.QueryRowContext(ctx,
            `SELECT EXISTS (SELECT 1 FROM schema_migrations_auth WHERE version = $1)`, name,
        ).Scan(&exists); err != nil {
            _ = tx.Rollback()
            return fmt.Errorf("check migration %s: %w", name, err)
        }
        if exists {
            _ = tx.Rollback()
            continue
        }

        sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
        if err != nil {
            _ = tx.Rollback()
            return fmt.Errorf("read migration %s: %w", name, err)
        }

        if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
            _ = tx.Rollback()
            return fmt.Errorf("apply migration %s: %w", name, err)
        }

        if _, err := tx.ExecContext(ctx,
            `INSERT INTO schema_migrations_auth (version) VALUES ($1)`, name,
        ); err != nil {
            _ = tx.Rollback()
            return fmt.Errorf("record migration %s: %w", name, err)
        }

        if err := tx.Commit(); err != nil {
            return fmt.Errorf("commit migration %s: %w", name, err)
        }
    }

    return nil
}
