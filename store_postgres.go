package secureauth

import (
    "context"
    "crypto/sha256"
    "database/sql"
    "embed"
    "encoding/base64"
    "fmt"
    "time"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type PostgresStore struct {
    db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
    return &PostgresStore{db: db}
}

func (s *PostgresStore) GetUserByGoogleSub(ctx context.Context, sub string) (*User, error) {
    row := s.db.QueryRowContext(ctx, `
        SELECT id, google_sub, email, name, avatar_url, created_at, updated_at
        FROM users
        WHERE google_sub = $1
    `, sub)

    u := &User{}
    if err := row.Scan(&u.ID, &u.GoogleSub, &u.Email, &u.Name, &u.AvatarURL, &u.CreatedAt, &u.UpdatedAt); err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, err
    }
    return u, nil
}

func (s *PostgresStore) CreateUser(ctx context.Context, u *User) error {
    return s.db.QueryRowContext(ctx, `
        INSERT INTO users (google_sub, email, name, avatar_url)
        VALUES ($1, $2, $3, $4)
        RETURNING id, created_at, updated_at
    `, u.GoogleSub, u.Email, u.Name, u.AvatarURL).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
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
    if err := row.Scan(
        &sess.ID, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt, &sess.LastSeenAt, &sess.UserAgent, &sess.IPAddress,
        &user.ID, &user.GoogleSub, &user.Email, &user.Name, &user.AvatarURL, &user.CreatedAt, &user.UpdatedAt,
    ); err != nil {
        if err == sql.ErrNoRows {
            return nil, nil, nil
        }
        return nil, nil, err
    }

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

// hashSessionToken hashes the session token so we don't store it in plaintext in the DB.
func hashSessionToken(token string) string {
    sum := sha256.Sum256([]byte(token))
    return base64.RawURLEncoding.EncodeToString(sum[:])
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
