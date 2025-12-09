````markdown
# secureauth

A reusable Go module for **Google Sign-In + DB-backed sessions** with:

- No passwords (Google OAuth2 / OpenID Connect only)
- Server-side sessions (opaque tokens, **hashed in DB**)
- Built-in DB migrations (`users`, `sessions`)
- Login page (Tailwind + Alpine)
- Middleware for protecting routes
- CSRF protection for logout
- Sensible security defaults

Designed for Go web apps using chi, htmx, and AlpineJS.

---

## Features

- **Google OAuth2 / OpenID Connect**
  - Uses `openid email profile` scopes
  - Verifies ID token signature, `aud`, `iss`, `exp`
  - Enforces `email_verified = true`
  - Uses OIDC `state` and `nonce` (CSRF + replay protection)

- **Sessions**
  - Random opaque session tokens (stored in cookie)
  - Tokens **hashed** with SHA-256 in DB (`session_token_hash`)
  - Sliding expiration with configurable TTL
  - HttpOnly, SameSite=Lax cookies
  - Optional `Secure` flag for HTTPS-only cookies

- **Database**
  - `users` table keyed by Google `sub`
  - `sessions` table keyed by `session_token_hash`
  - Embedded SQL migrations, applied via `Migrate`

- **HTTP integration**
  - `LoginPageHandler` – built-in login page with “Sign in with Google”
  - `GoogleLoginHandler` – starts OAuth flow
  - `GoogleCallbackHandler` – handles callback, creates user + session
  - `LogoutHandler` – deletes session, clears cookies (CSRF-protected)
  - `RequireAuth` middleware – protects routes and injects user into context
  - `LoadUser` middleware – optional, attaches user if logged in but doesn’t enforce

---

## Install

In your **app** module:

```bash
go get github.com/ashishbishnoi18/secureauth@latest
````

(Replace `github.com/ashishbishnoi18/secureauth` with your actual module path if different.)

In `go.mod` you’ll see something like:

```go
require github.com/ashishbishnoi18/secureauth v0.1.0
```

If you are developing the module locally side-by-side with an app, add a `replace`:

```go
replace github.com/ashishbishnoi18/secureauth => ../secureauth
```

---

## Environment variables

The module expects config via environment variables. You can load a `.env` file using `github.com/joho/godotenv` in your app.

### Required

* `GOOGLE_CLIENT_ID`
* `GOOGLE_CLIENT_SECRET`
* `GOOGLE_REDIRECT_URL` – e.g. `http://localhost:8080/auth/google/callback`

### Recommended app config

* `APP_BASE_URL` – e.g. `http://localhost:8080` or `https://yourapp.com`

### Session config

* `SESSION_COOKIE_NAME` – default: `app_session`
* `SESSION_COOKIE_DOMAIN` – default: empty → current host
* `SESSION_TTL_HOURS` – default: `720` (30 days)
* `SESSION_SECURE_COOKIES`

  * `true` in production with HTTPS
  * `false` for localhost dev

### Auth route paths (optional overrides)

* `LOGIN_PATH` – default: `/login`
* `AFTER_LOGIN_PATH` – default: `/`
* `AFTER_LOGOUT_PATH` – default: `/login`

### Proxy config

* `TRUST_PROXY_HEADERS` – default: `false`
  Set to `true` only if you are behind a **trusted** reverse proxy and want to rely on `X-Forwarded-For` for client IP.

### Safety check

If `APP_BASE_URL` starts with `https://` and `SESSION_SECURE_COOKIES=false`, `ConfigFromEnv` will return an error.

In production you **must** use secure cookies.

---

## Database schema

The module currently ships with a **Postgres**-oriented implementation.

It provides:

* Embedded SQL migrations
* A `Migrate` function that applies them
* A `PostgresStore` that implements the `Store` interface

Tables created:

```sql
-- users
CREATE TABLE IF NOT EXISTS users (
    id          BIGSERIAL PRIMARY KEY,
    google_sub  TEXT NOT NULL UNIQUE,
    email       TEXT NOT NULL,
    name        TEXT,
    avatar_url  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- sessions
CREATE TABLE IF NOT EXISTS sessions (
    id                 BIGSERIAL PRIMARY KEY,
    session_token_hash TEXT NOT NULL UNIQUE,
    user_id            BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_agent         TEXT,
    ip_address         INET
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
```

Migrations are applied transactionally via `Migrate(ctx, db)`.

---

## Quick start: new app

### 1. Load config and DB, run migrations

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
    // Load .env for local development (optional)
    _ = godotenv.Load()

    cfg, err := secureauth.ConfigFromEnv()
    if err != nil {
        log.Fatalf("config: %v", err)
    }

    dsn := os.Getenv("DATABASE_URL")
    if dsn == "" {
        dsn = "postgres://user:pass@localhost:5432/myapp?sslmode=disable"
    }

    db, err := sql.Open("postgres", dsn)
    if err != nil {
        log.Fatalf("db open: %v", err)
    }
    defer db.Close()

    if err := db.Ping(); err != nil {
        log.Fatalf("db ping: %v", err)
    }

    // Apply auth migrations
    if err := secureauth.Migrate(context.Background(), db); err != nil {
        log.Fatalf("auth migrations: %v", err)
    }

    // ...
}
```

### 2. Build `Store` and `Auth`

```go
store := secureauth.NewPostgresStore(db)

auth, err := secureauth.New(context.Background(), cfg, store)
if err != nil {
    log.Fatalf("auth init: %v", err)
}
```

### 3. Wire routes (example with `chi`)

```go
import (
    "net/http"
    "github.com/go-chi/chi/v5"
)

func main() {
    // ... config, db, migrations, store, auth

    r := chi.NewRouter()

    // Public routes
    r.Get(cfg.LoginPath, auth.LoginPageHandler)
    r.Get("/auth/google/login", auth.GoogleLoginHandler)
    r.Get("/auth/google/callback", auth.GoogleCallbackHandler)

    // Logout (POST)
    r.Post("/auth/logout", auth.LogoutHandler)

    // Protected group
    r.Group(func(pr chi.Router) {
        pr.Use(auth.RequireAuth)

        pr.Get("/", func(w http.ResponseWriter, r *http.Request) {
            user := secureauth.CurrentUser(r)
            w.Write([]byte("Hello, " + user.Email))
        })
    })

    log.Fatal(http.ListenAndServe(":8080", r))
}
```

At this point:

* `/login` renders the built-in login page
* Clicking “Continue with Google” starts the OAuth flow
* After successful login:

  * A `users` row and a `sessions` row are created
  * A secure session cookie is set
  * The user is redirected to `/`
* `/` is protected by `RequireAuth`

---

## Using the current user in handlers

Inside any handler that runs after `RequireAuth`:

```go
func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    user := secureauth.CurrentUser(r)
    if user == nil {
        // Should not happen if RequireAuth is used, but be defensive
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    fmt.Fprintf(w, "Welcome, %s (%s)", user.Name, user.Email)
}
```

`RequireAuth` does the heavy lifting:

* Reads the session cookie
* Validates and possibly extends the session
* Loads the `User` from the DB
* Attaches `*User` to the request context

If you just want to *optionally* attach the user without enforcing login, use:

```go
r.With(auth.LoadUser).Get("/some-route", handler)
```

and call `secureauth.CurrentUser(r)` inside that handler.

---

## Logout + CSRF

`LogoutHandler`:

* Requires a CSRF token (double-submit cookie pattern)
* Deletes the session row from DB by token
* Clears the session cookie and CSRF cookie
* Redirects to `AFTER_LOGOUT_PATH` (default `/login`)

On login, the module sets a non-HttpOnly CSRF cookie:

* Name: `SESSION_COOKIE_NAME + "_csrf"`
  e.g. if `SESSION_COOKIE_NAME=myapp_session`, cookie is `myapp_session_csrf`
* Value: random token

Your logout form should read this cookie and send it back as `csrf_token` (form field) or `X-CSRF-Token` header.

### Simple logout form example

```html
<form method="post" action="/auth/logout">
  <input type="hidden" name="csrf_token" id="logoutCsrf">
  <button type="submit">Logout</button>
</form>

<script>
  function getCookie(name) {
    const m = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
    return m ? m.pop() : '';
  }

  document.addEventListener('DOMContentLoaded', function () {
    var cookieName = "myapp_session_csrf"; // SESSION_COOKIE_NAME + "_csrf"
    var token = getCookie(cookieName);
    var field = document.getElementById('logoutCsrf');
    if (field && token) {
      field.value = token;
    }
  });
</script>
```

With htmx, you can also send the token via headers; the handler accepts both form field and header.

---

## Security notes

* **Session tokens hashed in DB**
  Cookies carry the opaque random token; DB stores `SHA-256(token)` (base64).
  This reduces the impact if your DB is ever leaked.

* **HTTPS in production**
  When `APP_BASE_URL` uses `https://`, you must set `SESSION_SECURE_COOKIES=true`.
  If not, `ConfigFromEnv` will fail.

* **Trusting proxies**
  Only set `TRUST_PROXY_HEADERS=true` when you are behind a trusted reverse proxy (e.g. Nginx, HAProxy, Cloudflare) that sets `X-Forwarded-For`.
  Otherwise, client IP is taken from `RemoteAddr`.

* **Email domain restrictions (optional)**
  If you want to allow only certain domains (e.g. `@yourcompany.com`), you can fork the module and add a check in `GoogleCallbackHandler` after reading `claims.Email`.

---

## Typical flow in a new project

1. Add the module:

   ```bash
   go get github.com/ashishbishnoi18/secureauth@latest
   ```

2. Create `.env` with:

   * Google client ID, secret, redirect URL
   * Session settings
   * APP_BASE_URL

3. In `main.go`:

   * Load `.env`
   * Call `ConfigFromEnv()`
   * Open DB and run `secureauth.Migrate`
   * Create `PostgresStore` and `Auth`
   * Wire handlers and middleware as shown above

4. Implement templates and handlers that read the current user via `secureauth.CurrentUser(r)`.

From then on, every new project uses the **same** auth behavior by just repeating this wiring; you never reimplement login, sessions, or Google OAuth per project.

---

```
::contentReference[oaicite:0]{index=0}
```
