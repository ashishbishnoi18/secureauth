package secureauth

import (
    "context"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    _ "embed"
    "encoding/base64"
    "errors"
    "fmt"
    "log"
    "net"
    "net/http"
    "strings"
    "time"
)

//go:embed templates/magic_link_verify.html
var magicLinkVerifyHTML string

//go:embed templates/magic_link_sent.html
var magicLinkSentHTML string

//go:embed templates/magic_link_error.html
var magicLinkErrorHTML string

// MagicLinkAuth handles magic link authentication.
type MagicLinkAuth struct {
    cfg             Config
    store           Store
    emailSender     EmailSender
    emailRateLimiter *EmailRateLimiter
    ipRateLimiter    *IPRateLimiter
}

// NewMagicLinkAuth creates a new magic link authenticator.
func NewMagicLinkAuth(cfg Config, store Store, emailSender EmailSender) *MagicLinkAuth {
    return &MagicLinkAuth{
        cfg:              cfg,
        store:            store,
        emailSender:      emailSender,
        emailRateLimiter: NewEmailRateLimiter(cfg.MagicLinkRateLimit),
        ipRateLimiter:    NewIPRateLimiter(30), // 30 requests per minute per IP
    }
}

// EmailStartHandler handles POST /auth/email/start
// Accepts an email address and sends a magic link.
// Always returns success to prevent email enumeration.
func (m *MagicLinkAuth) EmailStartHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    ctx := r.Context()
    clientIP := m.clientIP(r)

    // IP rate limiting
    if !m.ipRateLimiter.Allow(clientIP) {
        log.Printf("[MAGIC_LINK] IP rate limit exceeded: %s", clientIP)
        // Still return success to prevent enumeration
        m.renderSentPage(w)
        return
    }

    // Parse form
    if err := r.ParseForm(); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }

    email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
    if email == "" || !isValidEmail(email) {
        // Return success anyway to prevent enumeration
        m.renderSentPage(w)
        return
    }

    // Email rate limiting
    if !m.emailRateLimiter.Allow(email) {
        log.Printf("[MAGIC_LINK] Email rate limit exceeded: %s", email)
        // Still return success to prevent enumeration
        m.renderSentPage(w)
        return
    }

    // Generate token
    token, err := generateMagicLinkToken()
    if err != nil {
        log.Printf("[MAGIC_LINK] Failed to generate token: %v", err)
        m.renderSentPage(w)
        return
    }

    tokenHash := m.hashToken(token)
    expiresAt := time.Now().Add(m.cfg.MagicLinkTTL)

    // Store the magic link
    magicLink := &MagicLink{
        Email:            email,
        TokenHash:        tokenHash,
        ExpiresAt:        expiresAt,
        RequestIP:        clientIP,
        RequestUserAgent: r.UserAgent(),
    }

    if err := m.store.CreateMagicLink(ctx, magicLink); err != nil {
        log.Printf("[MAGIC_LINK] Failed to create magic link: %v", err)
        m.renderSentPage(w)
        return
    }

    // Build the magic link URL
    linkURL := fmt.Sprintf("%s/auth/email/verify?token=%s", m.cfg.AppBaseURL, token)

    // Send the email
    expiryMinutes := int(m.cfg.MagicLinkTTL.Minutes())
    if err := m.emailSender.SendMagicLink(ctx, email, linkURL, expiryMinutes); err != nil {
        log.Printf("[MAGIC_LINK] Failed to send email to %s: %v", email, err)
        // Don't expose the error to the user
    } else {
        log.Printf("[MAGIC_LINK] Magic link sent to %s", email)
    }

    m.renderSentPage(w)
}

// EmailVerifyHandler handles GET /auth/email/verify
// Shows a confirmation page where the user must click to confirm sign-in.
// This mitigates email link scanners that might consume the token.
func (m *MagicLinkAuth) EmailVerifyHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    token := r.URL.Query().Get("token")
    if token == "" {
        m.renderErrorPage(w, "Invalid or missing token")
        return
    }

    // Validate token exists and is not expired/used
    tokenHash := m.hashToken(token)
    magicLink, err := m.store.GetMagicLinkByTokenHash(r.Context(), tokenHash)
    if err != nil {
        log.Printf("[MAGIC_LINK] Error looking up token: %v", err)
        m.renderErrorPage(w, "An error occurred. Please try again.")
        return
    }

    if magicLink == nil {
        m.renderErrorPage(w, "This link is invalid or has already been used.")
        return
    }

    if magicLink.UsedAt != nil {
        m.renderErrorPage(w, "This link has already been used. Please request a new one.")
        return
    }

    if time.Now().After(magicLink.ExpiresAt) {
        m.renderErrorPage(w, "This link has expired. Please request a new one.")
        return
    }

    // Show confirmation page
    m.renderVerifyPage(w, token)
}

// EmailConsumeHandler handles POST /auth/email/consume
// Consumes the magic link token, creates a session, and redirects.
func (m *MagicLinkAuth) EmailConsumeHandler(a *Auth) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
            return
        }

        ctx := r.Context()
        clientIP := m.clientIP(r)

        if err := r.ParseForm(); err != nil {
            m.renderErrorPage(w, "Invalid request")
            return
        }

        token := r.FormValue("token")
        if token == "" {
            m.renderErrorPage(w, "Invalid or missing token")
            return
        }

        // Look up and validate the token
        tokenHash := m.hashToken(token)
        magicLink, err := m.store.GetMagicLinkByTokenHash(ctx, tokenHash)
        if err != nil {
            log.Printf("[MAGIC_LINK] Error looking up token for consume: %v", err)
            m.renderErrorPage(w, "An error occurred. Please try again.")
            return
        }

        if magicLink == nil {
            m.renderErrorPage(w, "This link is invalid or has already been used.")
            return
        }

        if magicLink.UsedAt != nil {
            m.renderErrorPage(w, "This link has already been used. Please request a new one.")
            return
        }

        if time.Now().After(magicLink.ExpiresAt) {
            m.renderErrorPage(w, "This link has expired. Please request a new one.")
            return
        }

        // Consume the token (mark as used)
        if err := m.store.ConsumeMagicLink(ctx, magicLink.ID, clientIP, r.UserAgent()); err != nil {
            log.Printf("[MAGIC_LINK] Failed to consume token: %v", err)
            m.renderErrorPage(w, "This link has already been used. Please request a new one.")
            return
        }

        log.Printf("[MAGIC_LINK] Token consumed for email: %s", magicLink.Email)

        // Find or create user by email
        user, err := m.findOrCreateUserByEmail(ctx, magicLink.Email)
        if err != nil {
            log.Printf("[MAGIC_LINK] Failed to find/create user: %v", err)
            m.renderErrorPage(w, "An error occurred. Please try again.")
            return
        }

        // Create session
        if err := a.createSessionForUser(w, r, user); err != nil {
            log.Printf("[MAGIC_LINK] Failed to create session: %v", err)
            m.renderErrorPage(w, "An error occurred. Please try again.")
            return
        }

        log.Printf("[MAGIC_LINK] User logged in via magic link: user_id=%d email=%s", user.ID, user.Email)

        // Redirect to app
        http.Redirect(w, r, m.cfg.AfterLoginPath, http.StatusSeeOther)
    }
}

// ForgotPasswordHandler handles POST /forgot-password
// Same as EmailStartHandler - just sends a magic link.
func (m *MagicLinkAuth) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
    // "Forgot password" in a passwordless system is the same as "send me a magic link"
    m.EmailStartHandler(w, r)
}

// findOrCreateUserByEmail finds an existing user by email or creates a new one.
// This implements the email linking policy:
// - If any identity with this email exists and is verified, use that user
// - If multiple users have the same verified email (shouldn't happen), fail safely
// - If no user exists, create a new one with an email identity
func (m *MagicLinkAuth) findOrCreateUserByEmail(ctx context.Context, email string) (*User, error) {
    // Check for existing identities with this email
    identities, err := m.store.GetIdentitiesByEmail(ctx, email)
    if err != nil {
        return nil, fmt.Errorf("get identities by email: %w", err)
    }

    if len(identities) > 0 {
        // Check if all identities point to the same user
        userID := identities[0].UserID
        for _, id := range identities[1:] {
            if id.UserID != userID {
                // This shouldn't happen if linking is working correctly
                return nil, fmt.Errorf("ambiguous email: multiple users (%d, %d) have verified email %s", userID, id.UserID, email)
            }
        }

        // Get the user
        user, err := m.store.GetUserByID(ctx, userID)
        if err != nil {
            return nil, fmt.Errorf("get user by id: %w", err)
        }
        if user == nil {
            return nil, fmt.Errorf("user not found for identity: user_id=%d", userID)
        }

        // Check if there's already an email identity for this user
        hasEmailIdentity := false
        for _, id := range identities {
            if id.Provider == "email" {
                hasEmailIdentity = true
                break
            }
        }

        // If user exists (e.g., from Google) but no email identity, create one
        if !hasEmailIdentity {
            emailIdentity := &Identity{
                UserID:          user.ID,
                Provider:        "email",
                ProviderSubject: email, // For email provider, subject is the email itself
                Email:           email,
                EmailVerified:   true,
            }
            if err := m.store.CreateIdentity(ctx, emailIdentity); err != nil {
                if errors.Is(err, ErrDuplicateVerifiedEmail) {
                    // Security: another user already has this verified email.
                    // This should not happen with proper linking, but fail closed.
                    corrID := generateCorrelationID()
                    log.Printf("[MAGIC_LINK] SECURITY: duplicate verified email on identity create, corr_id=%s user_id=%d", corrID, user.ID)
                    return nil, fmt.Errorf("account conflict [ref: %s]", corrID)
                }
                log.Printf("[MAGIC_LINK] Warning: failed to create email identity for existing user: %v", err)
                // Continue anyway - the user already has a verified identity
            } else {
                log.Printf("[MAGIC_LINK] Created email identity for existing user: user_id=%d email=%s", user.ID, email)
            }
        }

        return user, nil
    }

    // No existing user - create a new one
    user, err := m.store.CreateUserMinimal(ctx, email, "")
    if err != nil {
        return nil, fmt.Errorf("create user: %w", err)
    }

    // Create email identity
    emailIdentity := &Identity{
        UserID:          user.ID,
        Provider:        "email",
        ProviderSubject: email,
        Email:           email,
        EmailVerified:   true,
    }
    if err := m.store.CreateIdentity(ctx, emailIdentity); err != nil {
        if errors.Is(err, ErrDuplicateVerifiedEmail) {
            // Security: another user already has this verified email.
            // Fail closed with generic error.
            corrID := generateCorrelationID()
            log.Printf("[MAGIC_LINK] SECURITY: duplicate verified email on new user identity, corr_id=%s user_id=%d", corrID, user.ID)
            return nil, fmt.Errorf("account conflict [ref: %s]", corrID)
        }
        return nil, fmt.Errorf("create identity: %w", err)
    }

    log.Printf("[MAGIC_LINK] Created new user via magic link: user_id=%d email=%s", user.ID, email)
    return user, nil
}

// hashToken creates an HMAC-SHA256 hash of the token using the secret.
func (m *MagicLinkAuth) hashToken(token string) string {
    h := hmac.New(sha256.New, []byte(m.cfg.MagicLinkSecret))
    h.Write([]byte(token))
    return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// verifyTokenHash performs constant-time comparison of token hashes.
func (m *MagicLinkAuth) verifyTokenHash(token, expectedHash string) bool {
    actualHash := m.hashToken(token)
    return subtle.ConstantTimeCompare([]byte(actualHash), []byte(expectedHash)) == 1
}

func (m *MagicLinkAuth) renderSentPage(w http.ResponseWriter) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    _, _ = w.Write([]byte(magicLinkSentHTML))
}

func (m *MagicLinkAuth) renderVerifyPage(w http.ResponseWriter, token string) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    // Replace the token placeholder in the template
    html := strings.ReplaceAll(magicLinkVerifyHTML, "{{TOKEN}}", token)
    _, _ = w.Write([]byte(html))
}

func (m *MagicLinkAuth) renderErrorPage(w http.ResponseWriter, message string) {
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.WriteHeader(http.StatusBadRequest)
    html := strings.ReplaceAll(magicLinkErrorHTML, "{{ERROR_MESSAGE}}", message)
    _, _ = w.Write([]byte(html))
}

func (m *MagicLinkAuth) clientIP(r *http.Request) string {
    if m.cfg.TrustProxyHeaders {
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

// generateMagicLinkToken generates a cryptographically secure random token.
func generateMagicLinkToken() (string, error) {
    b := make([]byte, 32) // 256 bits of entropy
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.RawURLEncoding.EncodeToString(b), nil
}

// isValidEmail performs basic email validation.
func isValidEmail(email string) bool {
    // Basic check: must have @ and a dot after it
    at := strings.Index(email, "@")
    if at < 1 {
        return false
    }
    dot := strings.LastIndex(email, ".")
    if dot < at+2 || dot >= len(email)-1 {
        return false
    }
    return true
}
