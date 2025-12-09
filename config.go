package secureauth

import (
    "fmt"
    "os"
    "strconv"
    "strings"
    "time"
)

type Config struct {
    GoogleClientID     string
    GoogleClientSecret string
    RedirectURL        string // e.g. https://yourapp.com/auth/google/callback
    AppBaseURL         string // e.g. https://yourapp.com

    CookieName    string
    CookieDomain  string
    SessionTTL    time.Duration
    SecureCookies bool

    LoginPath       string // e.g. "/login"
    AfterLoginPath  string // e.g. "/"
    AfterLogoutPath string // e.g. "/login"

    TrustProxyHeaders bool // if true, use X-Forwarded-For for client IP
}

// ConfigFromEnv expects the app to have loaded .env (e.g. via github.com/joho/godotenv)
// and reads standard environment variables.
//
// Required:
//   GOOGLE_CLIENT_ID
//   GOOGLE_CLIENT_SECRET
//   GOOGLE_REDIRECT_URL
//
// Optional (with defaults):
//   APP_BASE_URL             (default: "http://localhost:8080")
//   SESSION_COOKIE_NAME      (default: "app_session")
//   SESSION_COOKIE_DOMAIN    (default: "") -> current host
//   SESSION_TTL_HOURS        (default: 720 = 30 days)
//   SESSION_SECURE_COOKIES   (default: "false" for localhost)
//   LOGIN_PATH               (default: "/login")
//   AFTER_LOGIN_PATH         (default: "/")
//   AFTER_LOGOUT_PATH        (default: "/login")
//   TRUST_PROXY_HEADERS      (default: "false")
func ConfigFromEnv() (Config, error) {
    cfg := Config{}

    cfg.GoogleClientID = os.Getenv("GOOGLE_CLIENT_ID")
    cfg.GoogleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
    cfg.RedirectURL = os.Getenv("GOOGLE_REDIRECT_URL")

    if cfg.GoogleClientID == "" || cfg.GoogleClientSecret == "" || cfg.RedirectURL == "" {
        return Config{}, fmt.Errorf("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URL are required")
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
