package secureauth

import (
    "context"
    "time"
)

type User struct {
    ID        int64
    GoogleSub string // Deprecated: use identities table. Kept for backward compatibility.
    Email     string
    Name      string
    AvatarURL string

    CreatedAt time.Time
    UpdatedAt time.Time
}

type Session struct {
    ID           int64
    SessionToken string // plaintext token (only in memory, not stored in DB)
    UserID       int64
    CreatedAt    time.Time
    ExpiresAt    time.Time
    LastSeenAt   time.Time
    UserAgent    string
    IPAddress    string
}

// Identity represents an authentication identity for a user.
// A user can have multiple identities (e.g., Google, email magic link).
type Identity struct {
    ID              int64
    UserID          int64
    Provider        string // "google" or "email"
    ProviderSubject string // google "sub" or normalized email for email provider
    Email           string // normalized email (lowercase, trimmed)
    EmailVerified   bool

    CreatedAt time.Time
    UpdatedAt time.Time
}

// MagicLink represents a one-time login token sent via email.
type MagicLink struct {
    ID                int64
    Email             string     // normalized email
    TokenHash         string     // HMAC-SHA256 hash (not stored as plaintext token)
    Token             string     // plaintext token (only in memory, not stored in DB)
    CreatedAt         time.Time
    ExpiresAt         time.Time
    UsedAt            *time.Time // nil if not yet used
    RequestIP         string
    RequestUserAgent  string
    ConsumedIP        string
    ConsumedUserAgent string
}

// Store abstracts DB operations so you can swap implementations.
// All methods accept a context.Context for timeout/cancellation support.
type Store interface {
    // Users
    GetUserByGoogleSub(ctx context.Context, sub string) (*User, error)
    GetUserByID(ctx context.Context, id int64) (*User, error)
    CreateUser(ctx context.Context, u *User) error
    CreateUserMinimal(ctx context.Context, email, name string) (*User, error) // Creates user with just email
    UpdateUser(ctx context.Context, u *User) error

    // Sessions
    CreateSession(ctx context.Context, s *Session) error
    GetSessionByToken(ctx context.Context, token string) (*Session, *User, error)
    TouchSession(ctx context.Context, id int64, newExpiresAt time.Time) error
    DeleteSessionByToken(ctx context.Context, token string) error

    // Identities
    GetIdentityByProviderSubject(ctx context.Context, provider, subject string) (*Identity, error)
    GetIdentitiesByEmail(ctx context.Context, email string) ([]*Identity, error)
    CreateIdentity(ctx context.Context, i *Identity) error
    UpdateIdentity(ctx context.Context, i *Identity) error

    // Magic Links
    CreateMagicLink(ctx context.Context, m *MagicLink) error
    GetMagicLinkByTokenHash(ctx context.Context, tokenHash string) (*MagicLink, error)
    ConsumeMagicLink(ctx context.Context, id int64, consumedIP, consumedUserAgent string) error
    CountRecentMagicLinks(ctx context.Context, email string, since time.Time) (int, error)
    DeleteExpiredMagicLinks(ctx context.Context) error
}
