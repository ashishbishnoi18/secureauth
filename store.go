package secureauth

import (
    "context"
    "time"
)

type User struct {
    ID        int64
    GoogleSub string
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

// Store abstracts DB operations so you can swap implementations.
// All methods accept a context.Context for timeout/cancellation support.
type Store interface {
    // Users
    GetUserByGoogleSub(ctx context.Context, sub string) (*User, error)
    CreateUser(ctx context.Context, u *User) error
    UpdateUser(ctx context.Context, u *User) error

    // Sessions
    CreateSession(ctx context.Context, s *Session) error
    GetSessionByToken(ctx context.Context, token string) (*Session, *User, error)
    TouchSession(ctx context.Context, id int64, newExpiresAt time.Time) error
    DeleteSessionByToken(ctx context.Context, token string) error
}
