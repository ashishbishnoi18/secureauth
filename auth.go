package secureauth

import (
    "context"
    "crypto/rand"
    _ "embed"
    "encoding/base64"
    "errors"
    "fmt"
    "net"
    "net/http"
    "strings"
    "time"

    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
)

//go:embed templates/login.html
var loginPageHTML string

type Auth struct {
    cfg             Config
    store           Store
    oauthConfig     *oauth2.Config
    idTokenVerifier *oidc.IDTokenVerifier

    stateCookieName string
    nonceCookieName string
    csrfCookieName  string
}

// New initializes the Auth instance. Use context.Background() in your main().
func New(ctx context.Context, cfg Config, store Store) (*Auth, error) {
    if store == nil {
        return nil, errors.New("store is required")
    }

    // Discover Google OIDC endpoints
    provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
    if err != nil {
        return nil, fmt.Errorf("oidc provider: %w", err)
    }

    oauthCfg := &oauth2.Config{
        ClientID:     cfg.GoogleClientID,
        ClientSecret: cfg.GoogleClientSecret,
        RedirectURL:  cfg.RedirectURL,
        Endpoint:     google.Endpoint,
        Scopes: []string{
            oidc.ScopeOpenID,
            "profile",
            "email",
        },
    }

    verifier := provider.Verifier(&oidc.Config{
        ClientID: cfg.GoogleClientID,
    })

    a := &Auth{
        cfg:             cfg,
        store:           store,
        oauthConfig:     oauthCfg,
        idTokenVerifier: verifier,
        stateCookieName: cfg.CookieName + "_oauth_state",
        nonceCookieName: cfg.CookieName + "_oauth_nonce",
        csrfCookieName:  cfg.CookieName + "_csrf",
    }

    return a, nil
}

// LoginPageHandler serves the embedded login page.
func (a *Auth) LoginPageHandler(w http.ResponseWriter, r *http.Request) {
    // If already logged in, redirect quickly
    if a.currentUserFromSession(w, r) != nil {
        http.Redirect(w, r, a.cfg.AfterLoginPath, http.StatusSeeOther)
        return
    }

    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    _, _ = w.Write([]byte(loginPageHTML))
}

// GoogleLoginHandler starts the OAuth2 flow.
func (a *Auth) GoogleLoginHandler(w http.ResponseWriter, r *http.Request) {
    state, err := randomString(32)
    if err != nil {
        http.Error(w, "failed to start login", http.StatusInternalServerError)
        return
    }
    nonce, err := randomString(32)
    if err != nil {
        http.Error(w, "failed to start login", http.StatusInternalServerError)
        return
    }

    // Store state and nonce in HttpOnly cookies to protect against CSRF and replay
    http.SetCookie(w, &http.Cookie{
        Name:     a.stateCookieName,
        Value:    state,
        Path:     "/",
        HttpOnly: true,
        Secure:   a.cfg.SecureCookies,
        SameSite: http.SameSiteLaxMode,
        Expires:  time.Now().Add(10 * time.Minute),
    })

    http.SetCookie(w, &http.Cookie{
        Name:     a.nonceCookieName,
        Value:    nonce,
        Path:     "/",
        HttpOnly: true,
        Secure:   a.cfg.SecureCookies,
        SameSite: http.SameSiteLaxMode,
        Expires:  time.Now().Add(10 * time.Minute),
    })

    url := a.oauthConfig.AuthCodeURL(
        state,
        oauth2.AccessTypeOnline,
        oauth2.SetAuthURLParam("prompt", "select_account"),
        oauth2.SetAuthURLParam("nonce", nonce),
    )

    http.Redirect(w, r, url, http.StatusFound)
}

// GoogleCallbackHandler handles Google's redirect back with ?code & ?state.
func (a *Auth) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    state := r.URL.Query().Get("state")
    code := r.URL.Query().Get("code")

    if state == "" || code == "" {
        http.Error(w, "invalid callback", http.StatusBadRequest)
        return
    }

    // Check state cookie
    stateCookie, err := r.Cookie(a.stateCookieName)
    if err != nil || stateCookie.Value == "" || stateCookie.Value != state {
        http.Error(w, "invalid state", http.StatusBadRequest)
        return
    }

    // Check nonce cookie (will be compared against ID token claim later)
    nonceCookie, err := r.Cookie(a.nonceCookieName)
    if err != nil || nonceCookie.Value == "" {
        http.Error(w, "missing nonce", http.StatusBadRequest)
        return
    }
    expectedNonce := nonceCookie.Value

    // Clear state & nonce cookies
    http.SetCookie(w, &http.Cookie{
        Name:     a.stateCookieName,
        Value:    "",
        Path:     "/",
        HttpOnly: true,
        Secure:   a.cfg.SecureCookies,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   -1,
    })
    http.SetCookie(w, &http.Cookie{
        Name:     a.nonceCookieName,
        Value:    "",
        Path:     "/",
        HttpOnly: true,
        Secure:   a.cfg.SecureCookies,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   -1,
    })

    // Exchange code for tokens
    token, err := a.oauthConfig.Exchange(ctx, code)
    if err != nil {
        http.Error(w, "failed to exchange code", http.StatusInternalServerError)
        return
    }

    rawIDToken, ok := token.Extra("id_token").(string)
    if !ok || rawIDToken == "" {
        http.Error(w, "no id_token in response", http.StatusInternalServerError)
        return
    }

    idToken, err := a.idTokenVerifier.Verify(ctx, rawIDToken)
    if err != nil {
        http.Error(w, "failed to verify id_token", http.StatusInternalServerError)
        return
    }

    var claims struct {
        Sub           string `json:"sub"`
        Email         string `json:"email"`
        EmailVerified bool   `json:"email_verified"`
        Name          string `json:"name"`
        Picture       string `json:"picture"`
        Nonce         string `json:"nonce"`
    }
    if err := idToken.Claims(&claims); err != nil {
        http.Error(w, "failed to parse id_token claims", http.StatusInternalServerError)
        return
    }

    if claims.Sub == "" || claims.Email == "" || !claims.EmailVerified {
        http.Error(w, "invalid google account", http.StatusForbidden)
        return
    }

    // Verify nonce against cookie
    if claims.Nonce == "" || claims.Nonce != expectedNonce {
        http.Error(w, "invalid nonce", http.StatusForbidden)
        return
    }

    // Upsert user
    u, err := a.store.GetUserByGoogleSub(ctx, claims.Sub)
    if err != nil {
        http.Error(w, "db error", http.StatusInternalServerError)
        return
    }

    now := time.Now()
    if u == nil {
        u = &User{
            GoogleSub: claims.Sub,
            Email:     claims.Email,
            Name:      claims.Name,
            AvatarURL: claims.Picture,
        }
        if err := a.store.CreateUser(ctx, u); err != nil {
            http.Error(w, "failed to create user", http.StatusInternalServerError)
            return
        }
    } else {
        // Keep email/profile up to date
        u.Email = claims.Email
        u.Name = claims.Name
        u.AvatarURL = claims.Picture
        if err := a.store.UpdateUser(ctx, u); err != nil {
            http.Error(w, "failed to update user", http.StatusInternalServerError)
            return
        }
    }

    // Create session
    sessToken, err := randomString(64)
    if err != nil {
        http.Error(w, "failed to create session", http.StatusInternalServerError)
        return
    }

    sess := &Session{
        SessionToken: sessToken,
        UserID:       u.ID,
        ExpiresAt:    now.Add(a.cfg.SessionTTL),
        LastSeenAt:   now,
        UserAgent:    r.UserAgent(),
        IPAddress:    a.clientIP(r),
    }

    if err := a.store.CreateSession(ctx, sess); err != nil {
        http.Error(w, "failed to save session", http.StatusInternalServerError)
        return
    }

    // Set session cookie
    http.SetCookie(w, &http.Cookie{
        Name:     a.cfg.CookieName,
        Value:    sessToken,
        Path:     "/",
        HttpOnly: true,
        Secure:   a.cfg.SecureCookies,
        SameSite: http.SameSiteLaxMode,
        Expires:  sess.ExpiresAt,
    })

    // Set CSRF cookie (double-submit pattern)
    csrfToken, err := randomString(32)
    if err == nil {
        http.SetCookie(w, &http.Cookie{
            Name:     a.csrfCookieName,
            Value:    csrfToken,
            Path:     "/",
            HttpOnly: false, // must be readable by JS/form to submit back
            Secure:   a.cfg.SecureCookies,
            SameSite: http.SameSiteLaxMode,
            Expires:  sess.ExpiresAt,
        })
    }

    http.Redirect(w, r, a.cfg.AfterLoginPath, http.StatusSeeOther)
}

// LogoutHandler deletes the session from DB and clears the cookies.
// Requires a CSRF token either in form field "csrf_token" or header "X-CSRF-Token".
func (a *Auth) LogoutHandler(w http.ResponseWriter, r *http.Request) {
    // CSRF validation
    csrfCookie, err := r.Cookie(a.csrfCookieName)
    if err != nil || csrfCookie.Value == "" {
        http.Error(w, "missing csrf token", http.StatusForbidden)
        return
    }

    csrfToken := r.FormValue("csrf_token")
    if csrfToken == "" {
        csrfToken = r.Header.Get("X-CSRF-Token")
    }
    if csrfToken == "" || csrfToken != csrfCookie.Value {
        http.Error(w, "invalid csrf token", http.StatusForbidden)
        return
    }

    // Delete session by token
    cookie, err := r.Cookie(a.cfg.CookieName)
    if err == nil && cookie.Value != "" {
        _ = a.store.DeleteSessionByToken(r.Context(), cookie.Value)
    }

    // Clear session cookie
    http.SetCookie(w, &http.Cookie{
        Name:     a.cfg.CookieName,
        Value:    "",
        Path:     "/",
        HttpOnly: true,
        Secure:   a.cfg.SecureCookies,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   -1,
    })

    // Clear CSRF cookie
    http.SetCookie(w, &http.Cookie{
        Name:     a.csrfCookieName,
        Value:    "",
        Path:     "/",
        HttpOnly: false,
        Secure:   a.cfg.SecureCookies,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   -1,
    })

    http.Redirect(w, r, a.cfg.AfterLogoutPath, http.StatusSeeOther)
}

// RequireAuth is middleware that ensures a logged-in user; otherwise redirects to login.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := a.currentUserFromSession(w, r)
        if user == nil {
            http.Redirect(w, r, a.cfg.LoginPath, http.StatusSeeOther)
            return
        }

        ctx := WithUser(r.Context(), user)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// LoadUser attaches user to context if logged in, but does not enforce it.
func (a *Auth) LoadUser(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := a.currentUserFromSession(w, r)
        if user != nil {
            ctx := WithUser(r.Context(), user)
            next.ServeHTTP(w, r.WithContext(ctx))
            return
        }
        next.ServeHTTP(w, r)
    })
}

// currentUserFromSession reads cookie, validates session, does sliding expiration.
func (a *Auth) currentUserFromSession(w http.ResponseWriter, r *http.Request) *User {
    ctx := r.Context()

    cookie, err := r.Cookie(a.cfg.CookieName)
    if err != nil || cookie.Value == "" {
        return nil
    }

    sess, user, err := a.store.GetSessionByToken(ctx, cookie.Value)
    if err != nil || sess == nil || user == nil {
        return nil
    }

    now := time.Now()
    if now.After(sess.ExpiresAt) {
        // Expired: delete and clear cookie
        _ = a.store.DeleteSessionByToken(ctx, cookie.Value)
        http.SetCookie(w, &http.Cookie{
            Name:     a.cfg.CookieName,
            Value:    "",
            Path:     "/",
            HttpOnly: true,
            Secure:   a.cfg.SecureCookies,
            SameSite: http.SameSiteLaxMode,
            MaxAge:   -1,
        })
        return nil
    }

    // Sliding expiration: extend if close to expiry
    remaining := sess.ExpiresAt.Sub(now)
    if remaining < a.cfg.SessionTTL/2 {
        newExpiry := now.Add(a.cfg.SessionTTL)
        _ = a.store.TouchSession(ctx, sess.ID, newExpiry)
        // refresh cookie
        http.SetCookie(w, &http.Cookie{
            Name:     a.cfg.CookieName,
            Value:    cookie.Value,
            Path:     "/",
            HttpOnly: true,
            Secure:   a.cfg.SecureCookies,
            SameSite: http.SameSiteLaxMode,
            Expires:  newExpiry,
        })
    }

    return user
}

func (a *Auth) clientIP(r *http.Request) string {
    // If we explicitly trust proxy headers, use the first X-Forwarded-For entry.
    if a.cfg.TrustProxyHeaders {
        if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
            parts := strings.Split(xff, ",")
            if len(parts) > 0 {
                return strings.TrimSpace(parts[0])
            }
        }
    }

    host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        return r.RemoteAddr
    }
    return host
}

func randomString(n int) (string, error) {
    b := make([]byte, n)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.RawURLEncoding.EncodeToString(b), nil
}
