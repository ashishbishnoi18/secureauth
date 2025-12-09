package secureauth

import (
    "context"
    "net/http"
)

type contextKey string

const userContextKey contextKey = "secureauth_user"

func WithUser(ctx context.Context, u *User) context.Context {
    return context.WithValue(ctx, userContextKey, u)
}

func UserFromContext(ctx context.Context) *User {
    v := ctx.Value(userContextKey)
    if v == nil {
        return nil
    }
    if u, ok := v.(*User); ok {
        return u
    }
    return nil
}

// Convenience for handlers.
func CurrentUser(r *http.Request) *User {
    return UserFromContext(r.Context())
}
