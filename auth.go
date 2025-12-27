package secureauth

import (
    "context"
    "crypto/rand"
    _ "embed"
    "encoding/base64"
    "encoding/hex"
    "errors"
    "fmt"
    "log"
    "net"
    "net/http"
    "strings"
    "time"

    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/google"
)

// generateCorrelationID generates a short correlation ID for error tracing.
func generateCorrelationID() string {
    b := make([]byte, 8)
    if _, err := rand.Read(b); err != nil {
        return "unknown"
    }
    return hex.EncodeToString(b)
}

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

    // Magic link auth (optional)
    magicLink *MagicLinkAuth
}

// New initializes the Auth instance. Use context.Background() in your main().
// Google OAuth is optional if magic link auth is enabled.
func New(ctx context.Context, cfg Config, store Store) (*Auth, error) {
    if store == nil {
        return nil, errors.New("store is required")
    }

    a := &Auth{
        cfg:             cfg,
        store:           store,
        stateCookieName: cfg.CookieName + "_oauth_state",
        nonceCookieName: cfg.CookieName + "_oauth_nonce",
        csrfCookieName:  cfg.CookieName + "_csrf",
    }

    // Initialize Google OAuth if configured
    if cfg.GoogleConfigured() {
        provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
        if err != nil {
            return nil, fmt.Errorf("oidc provider: %w", err)
        }

        a.oauthConfig = &oauth2.Config{
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

        a.idTokenVerifier = provider.Verifier(&oidc.Config{
            ClientID: cfg.GoogleClientID,
        })
    }

    return a, nil
}

// SetMagicLinkAuth sets the magic link authenticator.
// Call this after New() if you want to enable magic link auth.
func (a *Auth) SetMagicLinkAuth(m *MagicLinkAuth) {
    a.magicLink = m
}

// MagicLinkEnabled returns true if magic link auth is configured.
func (a *Auth) MagicLinkEnabled() bool {
    return a.magicLink != nil
}

// MagicLink returns the magic link authenticator.
// Returns nil if magic link auth is not configured.
func (a *Auth) MagicLink() *MagicLinkAuth {
    return a.magicLink
}

// GoogleEnabled returns true if Google OAuth is configured.
func (a *Auth) GoogleEnabled() bool {
    return a.oauthConfig != nil
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
    if !a.GoogleEnabled() {
        http.Error(w, "Google login not configured", http.StatusNotFound)
        return
    }

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
    if !a.GoogleEnabled() {
        http.Error(w, "Google login not configured", http.StatusNotFound)
        return
    }

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

    // Normalize email
    normalizedEmail := strings.TrimSpace(strings.ToLower(claims.Email))

    // Find or create user via identity
    user, err := a.findOrCreateUserByGoogleIdentity(ctx, claims.Sub, normalizedEmail, claims.Name, claims.Picture)
    if err != nil {
        log.Printf("[GOOGLE_AUTH] Failed to find/create user: %v", err)
        http.Error(w, "failed to process login", http.StatusInternalServerError)
        return
    }

    // Create session
    if err := a.createSessionForUser(w, r, user); err != nil {
        log.Printf("[GOOGLE_AUTH] Failed to create session: %v", err)
        http.Error(w, "failed to create session", http.StatusInternalServerError)
        return
    }

    log.Printf("[GOOGLE_AUTH] User logged in: user_id=%d email=%s", user.ID, user.Email)

    http.Redirect(w, r, a.cfg.AfterLoginPath, http.StatusSeeOther)
}

// findOrCreateUserByGoogleIdentity handles the Google login flow with identity linking.
// If the user already exists (by google sub or email), it links/updates the identity.
// If not, it creates a new user and identity.
func (a *Auth) findOrCreateUserByGoogleIdentity(ctx context.Context, googleSub, email, name, picture string) (*User, error) {
    // First check if we have an identity for this Google sub
    identity, err := a.store.GetIdentityByProviderSubject(ctx, "google", googleSub)
    if err != nil {
        return nil, fmt.Errorf("get identity: %w", err)
    }

    if identity != nil {
        // Existing Google identity - get the user
        user, err := a.store.GetUserByID(ctx, identity.UserID)
        if err != nil {
            return nil, fmt.Errorf("get user: %w", err)
        }
        if user == nil {
            return nil, fmt.Errorf("user not found for identity")
        }

        // Update user info if changed
        if user.Email != email || user.Name != name || user.AvatarURL != picture {
            user.Email = email
            user.Name = name
            user.AvatarURL = picture
            if err := a.store.UpdateUser(ctx, user); err != nil {
                log.Printf("[GOOGLE_AUTH] Warning: failed to update user: %v", err)
            }
        }

        // Update identity email if changed
        if identity.Email != email {
            identity.Email = email
            if err := a.store.UpdateIdentity(ctx, identity); err != nil {
                log.Printf("[GOOGLE_AUTH] Warning: failed to update identity: %v", err)
            }
        }

        return user, nil
    }

    // No Google identity found - check if there's an existing user with this email
    existingIdentities, err := a.store.GetIdentitiesByEmail(ctx, email)
    if err != nil {
        return nil, fmt.Errorf("get identities by email: %w", err)
    }

    var user *User
    if len(existingIdentities) > 0 {
        // Link to existing user
        userID := existingIdentities[0].UserID
        // Verify all identities point to same user
        for _, id := range existingIdentities[1:] {
            if id.UserID != userID {
                return nil, fmt.Errorf("ambiguous email: multiple users have verified email %s", email)
            }
        }

        user, err = a.store.GetUserByID(ctx, userID)
        if err != nil {
            return nil, fmt.Errorf("get user by id: %w", err)
        }
        if user == nil {
            return nil, fmt.Errorf("user not found")
        }

        // Update user info
        user.Email = email
        user.Name = name
        user.AvatarURL = picture
        user.GoogleSub = googleSub // For backward compatibility
        if err := a.store.UpdateUser(ctx, user); err != nil {
            log.Printf("[GOOGLE_AUTH] Warning: failed to update user: %v", err)
        }

        log.Printf("[GOOGLE_AUTH] Linking Google identity to existing user: user_id=%d email=%s", user.ID, email)
    } else {
        // Check for legacy user by google_sub (for backward compatibility with existing users)
        user, err = a.store.GetUserByGoogleSub(ctx, googleSub)
        if err != nil {
            return nil, fmt.Errorf("get user by google sub: %w", err)
        }

        if user != nil {
            // Legacy user exists - update and continue
            user.Email = email
            user.Name = name
            user.AvatarURL = picture
            if err := a.store.UpdateUser(ctx, user); err != nil {
                log.Printf("[GOOGLE_AUTH] Warning: failed to update user: %v", err)
            }
        } else {
            // Create new user
            user = &User{
                GoogleSub: googleSub,
                Email:     email,
                Name:      name,
                AvatarURL: picture,
            }
            if err := a.store.CreateUser(ctx, user); err != nil {
                return nil, fmt.Errorf("create user: %w", err)
            }
            log.Printf("[GOOGLE_AUTH] Created new user: user_id=%d email=%s", user.ID, email)
        }
    }

    // Create the Google identity
    googleIdentity := &Identity{
        UserID:          user.ID,
        Provider:        "google",
        ProviderSubject: googleSub,
        Email:           email,
        EmailVerified:   true,
    }
    if err := a.store.CreateIdentity(ctx, googleIdentity); err != nil {
        if errors.Is(err, ErrDuplicateVerifiedEmail) {
            // Security: another user already has this verified email.
            // This should not happen with proper linking, but fail closed.
            corrID := generateCorrelationID()
            log.Printf("[GOOGLE_AUTH] SECURITY: duplicate verified email on identity create, corr_id=%s user_id=%d", corrID, user.ID)
            return nil, fmt.Errorf("account conflict [ref: %s]", corrID)
        }
        log.Printf("[GOOGLE_AUTH] Warning: failed to create google identity: %v", err)
        // Continue anyway - the user is created/updated
    }

    return user, nil
}

// createSessionForUser creates a session for the given user and sets cookies.
func (a *Auth) createSessionForUser(w http.ResponseWriter, r *http.Request, user *User) error {
    sessToken, err := randomString(64)
    if err != nil {
        return fmt.Errorf("generate session token: %w", err)
    }

    now := time.Now()
    expiresAt := now.Add(a.cfg.SessionTTL)

    // Apply absolute max TTL if configured
    if a.cfg.SessionMaxTTL > 0 {
        maxExpiry := now.Add(a.cfg.SessionMaxTTL)
        if expiresAt.After(maxExpiry) {
            expiresAt = maxExpiry
        }
    }

    sess := &Session{
        SessionToken: sessToken,
        UserID:       user.ID,
        ExpiresAt:    expiresAt,
        LastSeenAt:   now,
        UserAgent:    r.UserAgent(),
        IPAddress:    a.clientIP(r),
    }

    if err := a.store.CreateSession(r.Context(), sess); err != nil {
        return fmt.Errorf("create session: %w", err)
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

    return nil
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

        // Apply absolute max TTL if configured
        if a.cfg.SessionMaxTTL > 0 {
            maxExpiry := sess.CreatedAt.Add(a.cfg.SessionMaxTTL)
            if newExpiry.After(maxExpiry) {
                newExpiry = maxExpiry
            }
        }

        // Only extend if the new expiry is actually later
        if newExpiry.After(sess.ExpiresAt) {
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
