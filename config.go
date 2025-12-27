package secureauth

import (
    "fmt"
    "os"
    "strconv"
    "strings"
    "time"
)

type Config struct {
    // Google OIDC (optional if only using email auth)
    GoogleClientID     string
    GoogleClientSecret string
    RedirectURL        string // e.g. https://yourapp.com/auth/google/callback
    AppBaseURL         string // e.g. https://yourapp.com

    // Session cookies
    CookieName    string
    CookieDomain  string
    SessionTTL    time.Duration
    SecureCookies bool

    // Session limits (for magic link sessions)
    SessionMaxTTL time.Duration // Absolute max session lifetime (0 = no limit)

    // Routes
    LoginPath       string // e.g. "/login"
    AfterLoginPath  string // e.g. "/"
    AfterLogoutPath string // e.g. "/login"

    TrustProxyHeaders bool // if true, use X-Forwarded-For for client IP

    // Magic Link configuration
    EnableMagicLink    bool          // Enable email magic link authentication
    MagicLinkTTL       time.Duration // How long magic links are valid (default: 30 min)
    MagicLinkSecret    string        // Secret key for HMAC token hashing (required if magic link enabled)
    MagicLinkRateLimit int           // Max magic link requests per email per hour (default: 5)

    // SMTP configuration (required if magic link enabled)
    SMTPHost     string
    SMTPPort     int
    SMTPUsername string
    SMTPPassword string
    SMTPFrom     string
    SMTPFromName string
}

// ConfigFromEnv expects the app to have loaded .env (e.g. via github.com/joho/godotenv)
// and reads standard environment variables.
//
// Required for Google auth:
//
//	GOOGLE_CLIENT_ID
//	GOOGLE_CLIENT_SECRET
//	GOOGLE_REDIRECT_URL
//
// Required for Magic Link auth:
//
//	MAGIC_LINK_ENABLED=true
//	MAGIC_LINK_SECRET (high-entropy secret for HMAC, at least 32 chars)
//	SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM
//
// Optional (with defaults):
//
//	APP_BASE_URL             (default: "http://localhost:8080")
//	SESSION_COOKIE_NAME      (default: "app_session")
//	SESSION_COOKIE_DOMAIN    (default: "") -> current host
//	SESSION_TTL_HOURS        (default: 720 = 30 days)
//	SESSION_MAX_TTL_HOURS    (default: 0 = no limit; set to 4380 for 6 months)
//	SESSION_SECURE_COOKIES   (default: "false" for localhost)
//	LOGIN_PATH               (default: "/login")
//	AFTER_LOGIN_PATH         (default: "/")
//	AFTER_LOGOUT_PATH        (default: "/login")
//	TRUST_PROXY_HEADERS      (default: "false")
//	MAGIC_LINK_TTL_MINUTES   (default: 30)
//	MAGIC_LINK_RATE_LIMIT    (default: 5 per email per hour)
//	SMTP_FROM_NAME           (default: "")
func ConfigFromEnv() (Config, error) {
    cfg := Config{}

    // Google OAuth (optional)
    cfg.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
    cfg.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
    cfg.RedirectURL = os.Getenv("GOOGLE_REDIRECT_URL")

    // Magic Link configuration
    enableMagicLinkStr := os.Getenv("MAGIC_LINK_ENABLED")
    if enableMagicLinkStr != "" {
        enabled, err := strconv.ParseBool(enableMagicLinkStr)
        if err != nil {
            return Config{}, fmt.Errorf("invalid MAGIC_LINK_ENABLED: %q", enableMagicLinkStr)
        }
        cfg.EnableMagicLink = enabled
    }

    cfg.MagicLinkSecret = os.Getenv("MAGIC_LINK_SECRET")

    magicLinkTTLStr := os.Getenv("MAGIC_LINK_TTL_MINUTES")
    if magicLinkTTLStr == "" {
        magicLinkTTLStr = "30"
    }
    magicLinkTTL, err := strconv.Atoi(magicLinkTTLStr)
    if err != nil || magicLinkTTL <= 0 {
        return Config{}, fmt.Errorf("invalid MAGIC_LINK_TTL_MINUTES: %q", magicLinkTTLStr)
    }
    cfg.MagicLinkTTL = time.Duration(magicLinkTTL) * time.Minute

    rateLimitStr := os.Getenv("MAGIC_LINK_RATE_LIMIT")
    if rateLimitStr == "" {
        rateLimitStr = "5"
    }
    rateLimit, err := strconv.Atoi(rateLimitStr)
    if err != nil || rateLimit <= 0 {
        return Config{}, fmt.Errorf("invalid MAGIC_LINK_RATE_LIMIT: %q", rateLimitStr)
    }
    cfg.MagicLinkRateLimit = rateLimit

    // SMTP configuration
    cfg.SMTPHost = os.Getenv("SMTP_HOST")
    smtpPortStr := os.Getenv("SMTP_PORT")
    if smtpPortStr != "" {
        port, err := strconv.Atoi(smtpPortStr)
        if err != nil || port <= 0 {
            return Config{}, fmt.Errorf("invalid SMTP_PORT: %q", smtpPortStr)
        }
        cfg.SMTPPort = port
    }
    cfg.SMTPUsername = os.Getenv("SMTP_USERNAME")
    cfg.SMTPPassword = os.Getenv("SMTP_PASSWORD")
    cfg.SMTPFrom = os.Getenv("SMTP_FROM")
    cfg.SMTPFromName = os.Getenv("SMTP_FROM_NAME")

    // Validate: at least one auth method must be configured
    googleConfigured := cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" && cfg.RedirectURL != ""

    if !googleConfigured && !cfg.EnableMagicLink {
        return Config{}, fmt.Errorf("at least one auth method must be configured: set GOOGLE_CLIENT_ID/SECRET/REDIRECT_URL or MAGIC_LINK_ENABLED=true")
    }

    // Validate magic link configuration
    if cfg.EnableMagicLink {
        if cfg.MagicLinkSecret == "" {
            return Config{}, fmt.Errorf("MAGIC_LINK_SECRET is required when MAGIC_LINK_ENABLED=true")
        }
        if len(cfg.MagicLinkSecret) < 32 {
            return Config{}, fmt.Errorf("MAGIC_LINK_SECRET must be at least 32 characters")
        }
        if cfg.SMTPHost == "" || cfg.SMTPPort == 0 || cfg.SMTPFrom == "" {
            return Config{}, fmt.Errorf("SMTP_HOST, SMTP_PORT, and SMTP_FROM are required when MAGIC_LINK_ENABLED=true")
        }
    }

    cfg.AppBaseURL = os.Getenv("APP_BASE_URL")
    if cfg.AppBaseURL == "" {
        cfg.AppBaseURL = "http://localhost:8080"
    }

    cfg.CookieName = os.Getenv("SESSION_COOKIE_NAME")
    if cfg.CookieName == "" {
        cfg.CookieName = "app_session"
    }

    cfg.CookieDomain = os.Getenv("SESSION_COOKIE_DOMAIN")

    ttlHoursStr := os.Getenv("SESSION_TTL_HOURS")
    if ttlHoursStr == "" {
        ttlHoursStr = "720" // 30 days
    }
    ttlHours, err := strconv.Atoi(ttlHoursStr)
    if err != nil || ttlHours <= 0 {
        return Config{}, fmt.Errorf("invalid SESSION_TTL_HOURS: %q", ttlHoursStr)
    }
    cfg.SessionTTL = time.Duration(ttlHours) * time.Hour

    // Session max TTL (absolute lifetime cap)
    maxTTLHoursStr := os.Getenv("SESSION_MAX_TTL_HOURS")
    if maxTTLHoursStr != "" {
        maxTTLHours, err := strconv.Atoi(maxTTLHoursStr)
        if err != nil || maxTTLHours < 0 {
            return Config{}, fmt.Errorf("invalid SESSION_MAX_TTL_HOURS: %q", maxTTLHoursStr)
        }
        cfg.SessionMaxTTL = time.Duration(maxTTLHours) * time.Hour
    }

    secureStr := os.Getenv("SESSION_SECURE_COOKIES")
    if secureStr == "" {
        secureStr = "false"
    }
    secure, err := strconv.ParseBool(secureStr)
    if err != nil {
        return Config{}, fmt.Errorf("invalid SESSION_SECURE_COOKIES: %q", secureStr)
    }
    cfg.SecureCookies = secure

    cfg.LoginPath = os.Getenv("LOGIN_PATH")
    if cfg.LoginPath == "" {
        cfg.LoginPath = "/login"
    }
    cfg.AfterLoginPath = os.Getenv("AFTER_LOGIN_PATH")
    if cfg.AfterLoginPath == "" {
        cfg.AfterLoginPath = "/"
    }
    cfg.AfterLogoutPath = os.Getenv("AFTER_LOGOUT_PATH")
    if cfg.AfterLogoutPath == "" {
        cfg.AfterLogoutPath = "/login"
    }

    trustProxyStr := os.Getenv("TRUST_PROXY_HEADERS")
    if trustProxyStr == "" {
        trustProxyStr = "false"
    }
    trustProxy, err := strconv.ParseBool(trustProxyStr)
    if err != nil {
        return Config{}, fmt.Errorf("invalid TRUST_PROXY_HEADERS: %q", trustProxyStr)
    }
    cfg.TrustProxyHeaders = trustProxy

    // Safety check: do not allow HTTPS base URL with insecure cookies
    if strings.HasPrefix(strings.ToLower(cfg.AppBaseURL), "https://") && !cfg.SecureCookies {
        return Config{}, fmt.Errorf("APP_BASE_URL is https but SESSION_SECURE_COOKIES=false; set SESSION_SECURE_COOKIES=true for secure deployment")
    }

    return cfg, nil
}

// SMTPConfigFromConfig extracts SMTP configuration from the main Config.
func (cfg Config) SMTPConfigFromConfig() SMTPConfig {
    return SMTPConfig{
        Host:     cfg.SMTPHost,
        Port:     cfg.SMTPPort,
        Username: cfg.SMTPUsername,
        Password: cfg.SMTPPassword,
        From:     cfg.SMTPFrom,
        FromName: cfg.SMTPFromName,
    }
}

// GoogleConfigured returns true if Google OAuth is configured.
func (cfg Config) GoogleConfigured() bool {
    return cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" && cfg.RedirectURL != ""
}
