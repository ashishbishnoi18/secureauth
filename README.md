# secureauth

A reusable Go module for **passwordless authentication** with:

- **Google Sign-In** (OAuth2 / OpenID Connect)
- **Email Magic Links** (passwordless email authentication)
- **Automatic account linking** (same email = same account)
- Server-side sessions (opaque tokens, **hashed in DB**)
- Built-in DB migrations (`users`, `sessions`, `identities`, `magic_links`)
- Login page (Tailwind + Alpine) with both Google and Email options
- Middleware for protecting routes
- CSRF protection
- Sensible security defaults

Designed for Go web apps using chi, htmx, and AlpineJS.

---

## Features

### Authentication Methods

- **Google OAuth2 / OpenID Connect**
  - Uses `openid email profile` scopes
  - Verifies ID token signature, `aud`, `iss`, `exp`
  - Enforces `email_verified = true`
  - Uses OIDC `state` and `nonce` (CSRF + replay protection)

- **Email Magic Links** (NEW)
  - Passwordless authentication via one-time email links
  - HMAC-SHA256 token hashing with server secret
  - Single-use tokens with configurable expiry (default 30 min)
  - Rate limiting per email and IP address
  - Confirmation page to mitigate email link scanners
  - No password storage or password reset needed

### Account Linking

**Same email = same account.** If a user:
1. First logs in with Google (e.g., `user@example.com`)
2. Later uses a magic link with the same email

They will be linked to the **same** internal user account automatically. This works in both directions.

### Sessions

- Random opaque session tokens (stored in cookie)
- Tokens **hashed** with SHA-256 in DB (`session_token_hash`)
- Sliding expiration with configurable TTL
- Optional absolute maximum session lifetime
- HttpOnly, SameSite=Lax cookies
- Optional `Secure` flag for HTTPS-only cookies

### Database

- Multi-provider identity support via `identities` table
- `users` table for core user data
- `sessions` table keyed by `session_token_hash`
- `magic_links` table for one-time login tokens
- Embedded SQL migrations, applied via `Migrate`
- Automatic migration of existing Google users to identities

---

## Install

```bash
go get github.com/ashishbishnoi18/secureauth@latest
```

---

## Environment Variables

### For Google Auth (optional if only using email)

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLIENT_ID` | Yes* | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Yes* | Google OAuth client secret |
| `GOOGLE_REDIRECT_URL` | Yes* | e.g. `http://localhost:8080/auth/google/callback` |

*Required if you want Google login

### For Magic Link Auth

| Variable | Required | Description |
|----------|----------|-------------|
| `MAGIC_LINK_ENABLED` | Yes | Set to `true` to enable email magic links |
| `MAGIC_LINK_SECRET` | Yes | High-entropy secret for HMAC (min 32 chars) |
| `MAGIC_LINK_TTL_MINUTES` | No | Link expiry time (default: 30) |
| `MAGIC_LINK_RATE_LIMIT` | No | Max requests per email per hour (default: 5) |
| `SMTP_HOST` | Yes* | SMTP server host |
| `SMTP_PORT` | Yes* | SMTP server port (e.g., 587) |
| `SMTP_USERNAME` | No | SMTP username |
| `SMTP_PASSWORD` | No | SMTP password |
| `SMTP_FROM` | Yes* | From email address |
| `SMTP_FROM_NAME` | No | From display name |

*Required if `MAGIC_LINK_ENABLED=true`

### App & Session Config

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_BASE_URL` | `http://localhost:8080` | Your app's base URL |
| `SESSION_COOKIE_NAME` | `app_session` | Cookie name |
| `SESSION_COOKIE_DOMAIN` | (empty) | Cookie domain |
| `SESSION_TTL_HOURS` | `720` (30 days) | Session sliding TTL |
| `SESSION_MAX_TTL_HOURS` | `0` (no limit) | Absolute max lifetime (set to 4380 for 6 months) |
| `SESSION_SECURE_COOKIES` | `false` | Set `true` for HTTPS |
| `LOGIN_PATH` | `/login` | Login page path |
| `AFTER_LOGIN_PATH` | `/` | Redirect after login |
| `AFTER_LOGOUT_PATH` | `/login` | Redirect after logout |
| `TRUST_PROXY_HEADERS` | `false` | Trust X-Forwarded-For |

### Validation

- At least one auth method must be configured (Google OR Magic Link)
- If `APP_BASE_URL` is HTTPS, `SESSION_SECURE_COOKIES` must be `true`
- `MAGIC_LINK_SECRET` must be at least 32 characters

---

## Quick Start

### 1. Configure Environment

```bash
# .env file

# Google (optional)
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URL=http://localhost:8080/auth/google/callback

# Magic Link
MAGIC_LINK_ENABLED=true
MAGIC_LINK_SECRET=your-32-char-minimum-secret-key-here

# SMTP
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=noreply@yourapp.com
SMTP_FROM_NAME=YourApp

# App
APP_BASE_URL=http://localhost:8080
DATABASE_URL=postgres://user:pass@localhost:5432/myapp?sslmode=disable
```

### 2. Initialize and Run Migrations

```go
package main

import (
    "context"
    "database/sql"
    "log"
    "os"

    _ "github.com/lib/pq"
    "github.com/joho/godotenv"
    "github.com/ashishbishnoi18/secureauth"
)

func main() {
    _ = godotenv.Load()

    cfg, err := secureauth.ConfigFromEnv()
    if err != nil {
        log.Fatalf("config: %v", err)
    }

    db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
    if err != nil {
        log.Fatalf("db: %v", err)
    }
    defer db.Close()

    // Apply migrations (creates users, sessions, identities, magic_links tables)
    if err := secureauth.Migrate(context.Background(), db); err != nil {
        log.Fatalf("migrations: %v", err)
    }

    // ... continue setup
}
```

### 3. Set Up Auth Handlers

```go
store := secureauth.NewPostgresStore(db)

auth, err := secureauth.New(context.Background(), cfg, store)
if err != nil {
    log.Fatalf("auth init: %v", err)
}

// Set up magic link auth if enabled
if cfg.EnableMagicLink {
    smtpCfg := cfg.SMTPConfigFromConfig()
    emailSender := secureauth.NewSMTPEmailSender(smtpCfg, cfg.AppBaseURL)
    magicLink := secureauth.NewMagicLinkAuth(cfg, store, emailSender)
    auth.SetMagicLinkAuth(magicLink)
}
```

### 4. Wire Routes (chi example)

```go
import (
    "net/http"
    "github.com/go-chi/chi/v5"
)

func main() {
    // ... setup code from above

    r := chi.NewRouter()

    // Login page (shows both Google and Email options)
    r.Get(cfg.LoginPath, auth.LoginPageHandler)

    // Google auth routes
    if auth.GoogleEnabled() {
        r.Get("/auth/google/login", auth.GoogleLoginHandler)
        r.Get("/auth/google/callback", auth.GoogleCallbackHandler)
    }

    // Magic link routes
    if auth.MagicLinkEnabled() {
        magicLink := auth.MagicLink()
        r.Post("/auth/email/start", magicLink.EmailStartHandler)
        r.Get("/auth/email/verify", magicLink.EmailVerifyHandler)
        r.Post("/auth/email/consume", magicLink.EmailConsumeHandler(auth))

        // "Forgot password" just sends a magic link (no passwords in this system)
        r.Post("/forgot-password", magicLink.ForgotPasswordHandler)
    }

    // Logout (requires CSRF token)
    r.Post("/auth/logout", auth.LogoutHandler)

    // Protected routes
    r.Group(func(pr chi.Router) {
        pr.Use(auth.RequireAuth)
        pr.Get("/", dashboardHandler)
        pr.Get("/profile", profileHandler)
    })

    log.Fatal(http.ListenAndServe(":8080", r))
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    user := secureauth.CurrentUser(r)
    w.Write([]byte("Hello, " + user.Email))
}
```

---

## Account Linking Behavior

The system automatically links accounts by verified email:

### Scenario 1: Google First, Then Magic Link

1. User signs in with Google (`user@example.com`)
2. User record created with Google identity
3. Later, user requests magic link for `user@example.com`
4. Magic link redeemed → finds existing user by email
5. Email identity added to same user account
6. Same `user_id` across both login methods

### Scenario 2: Magic Link First, Then Google

1. User signs in via magic link (`user@example.com`)
2. User record created with email identity
3. Later, user signs in with Google (same email)
4. Google login finds existing user by email
5. Google identity added to same user account
6. Same `user_id` across both login methods

### Edge Cases

- **Ambiguous emails**: If somehow multiple users have the same verified email (shouldn't happen with proper linking), login fails safely with an error log
- **Email normalization**: All emails are lowercased and trimmed before storage/comparison

---

## Forgot Password

In a passwordless system, "forgot password" simply sends a magic link. The `ForgotPasswordHandler` is an alias for `EmailStartHandler`:

```go
r.Post("/forgot-password", magicLink.ForgotPasswordHandler)
```

No password storage or reset functionality is implemented—users always sign in via Google or magic link.

---

## Security Features

### Token Security

- **Session tokens**: 64 bytes of random data, SHA-256 hashed in DB
- **Magic link tokens**: 32 bytes of random data, HMAC-SHA256 hashed with server secret
- **Constant-time comparison** for all token validation

### Rate Limiting

Magic link requests are rate limited:
- Per email: configurable (default 5/hour)
- Per IP: 30/minute

For distributed deployments, implement a Redis-based rate limiter.

### Link Scanner Mitigation

Magic link verification uses a two-step process:
1. `GET /auth/email/verify?token=...` → Shows confirmation page
2. `POST /auth/email/consume` with token → Actually consumes the token

This prevents email security scanners from accidentally consuming tokens.

### Enumeration Prevention

The magic link start endpoint always returns the same response (200 OK with "check your email" page) regardless of whether the email exists. This prevents user enumeration attacks.

### Cookies

- `HttpOnly` for session cookie (not readable by JavaScript)
- `SameSite=Lax` to prevent CSRF in most cases
- `Secure` flag when using HTTPS
- CSRF token in separate non-HttpOnly cookie for logout protection

---

## Database Schema

After running migrations, you'll have:

```sql
-- users (core user data)
CREATE TABLE users (
    id          BIGSERIAL PRIMARY KEY,
    google_sub  TEXT,              -- Legacy, nullable (for backward compat)
    email       TEXT NOT NULL,
    name        TEXT,
    avatar_url  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- identities (multi-provider support)
CREATE TABLE identities (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,           -- 'google' or 'email'
    provider_subject TEXT NOT NULL,          -- google 'sub' or email address
    email           TEXT NOT NULL,
    email_verified  BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_subject)
);

-- sessions
CREATE TABLE sessions (
    id                 BIGSERIAL PRIMARY KEY,
    session_token_hash TEXT NOT NULL UNIQUE,
    user_id            BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_agent         TEXT,
    ip_address         INET
);

-- magic_links
CREATE TABLE magic_links (
    id                  BIGSERIAL PRIMARY KEY,
    email               TEXT NOT NULL,
    token_hash          TEXT NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    used_at             TIMESTAMPTZ,
    request_ip          TEXT,
    request_user_agent  TEXT,
    consumed_ip         TEXT,
    consumed_user_agent TEXT
);
```

The migration automatically converts existing Google users to have identity records.

---

## Session Duration (6 Months)

For long-lived sessions (e.g., 6 months), configure:

```bash
SESSION_TTL_HOURS=720           # Sliding window: 30 days
SESSION_MAX_TTL_HOURS=4380      # Absolute max: ~6 months
```

Behavior:
- Session extends by `SESSION_TTL_HOURS` on activity (sliding)
- Session never exceeds `SESSION_MAX_TTL_HOURS` from creation (absolute cap)
- Set `SESSION_MAX_TTL_HOURS=0` for no absolute limit

---

## Custom Email Sender

Implement the `EmailSender` interface for custom email providers:

```go
type EmailSender interface {
    SendMagicLink(ctx context.Context, to, link string, expiresInMinutes int) error
}
```

Example with a third-party service:

```go
type SendGridSender struct {
    apiKey string
}

func (s *SendGridSender) SendMagicLink(ctx context.Context, to, link string, expiresInMinutes int) error {
    // Implement SendGrid API call
    return nil
}

// Use it:
emailSender := &SendGridSender{apiKey: os.Getenv("SENDGRID_API_KEY")}
magicLink := secureauth.NewMagicLinkAuth(cfg, store, emailSender)
```

For development, use the logging sender:

```go
emailSender := secureauth.NewLoggingEmailSender(log.Printf)
```

This prints magic links to the console instead of sending emails.

---

## Operational Considerations

### Email Deliverability

- Use a reputable SMTP provider (SendGrid, Mailgun, AWS SES)
- Configure SPF, DKIM, and DMARC for your sending domain
- Monitor bounce rates and spam complaints

### Rate Limiting in Production

The built-in rate limiter is in-memory. For multi-instance deployments:
- Implement a Redis-based rate limiter
- Or use an API gateway with rate limiting

### Reverse Proxy Headers

If behind a load balancer, set:
```bash
TRUST_PROXY_HEADERS=true
```

Ensure your proxy correctly sets `X-Forwarded-For`.

### Cleanup

Periodically clean up expired magic links:
```go
store.DeleteExpiredMagicLinks(context.Background())
```

Consider running this in a background goroutine or cron job.

---

## Testing

Run tests:

```bash
go test -v ./...
```

The test suite covers:
- Token generation and HMAC hashing
- Token expiry and single-use enforcement
- Account linking (Google → Magic Link)
- Enumeration prevention
- Rate limiting
- Email validation

---

## Migration from Google-Only

Existing apps using Google-only auth can add magic link support:

1. Update the module
2. Run migrations (adds `identities` and `magic_links` tables)
3. Existing Google users automatically get identity records
4. Add magic link routes and configuration
5. Existing sessions continue to work

No data loss or breaking changes for existing users.
