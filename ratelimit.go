package secureauth

import (
    "sync"
    "time"
)

// RateLimiter provides simple in-memory rate limiting.
// For distributed deployments, replace with Redis-based implementation.
type RateLimiter struct {
    mu      sync.Mutex
    entries map[string][]time.Time
    window  time.Duration
    limit   int
}

// NewRateLimiter creates a new rate limiter.
// window is the time window for rate limiting (e.g., 1 hour).
// limit is the maximum number of requests allowed within the window.
func NewRateLimiter(window time.Duration, limit int) *RateLimiter {
    rl := &RateLimiter{
        entries: make(map[string][]time.Time),
        window:  window,
        limit:   limit,
    }

    // Start background cleanup
    go rl.cleanup()

    return rl
}

// Allow checks if a request is allowed for the given key.
// Returns true if allowed, false if rate limit exceeded.
func (r *RateLimiter) Allow(key string) bool {
    r.mu.Lock()
    defer r.mu.Unlock()

    now := time.Now()
    cutoff := now.Add(-r.window)

    // Get existing entries and filter out expired ones
    entries := r.entries[key]
    var valid []time.Time
    for _, t := range entries {
        if t.After(cutoff) {
            valid = append(valid, t)
        }
    }

    // Check if we're at the limit
    if len(valid) >= r.limit {
        r.entries[key] = valid
        return false
    }

    // Add new entry
    valid = append(valid, now)
    r.entries[key] = valid
    return true
}

// Count returns the current count for a key within the window.
func (r *RateLimiter) Count(key string) int {
    r.mu.Lock()
    defer r.mu.Unlock()

    now := time.Now()
    cutoff := now.Add(-r.window)

    entries := r.entries[key]
    count := 0
    for _, t := range entries {
        if t.After(cutoff) {
            count++
        }
    }
    return count
}

// Reset clears all rate limit entries for a key.
func (r *RateLimiter) Reset(key string) {
    r.mu.Lock()
    defer r.mu.Unlock()
    delete(r.entries, key)
}

// cleanup periodically removes expired entries to prevent memory growth.
func (r *RateLimiter) cleanup() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        r.mu.Lock()
        now := time.Now()
        cutoff := now.Add(-r.window)

        for key, entries := range r.entries {
            var valid []time.Time
            for _, t := range entries {
                if t.After(cutoff) {
                    valid = append(valid, t)
                }
            }
            if len(valid) == 0 {
                delete(r.entries, key)
            } else {
                r.entries[key] = valid
            }
        }
        r.mu.Unlock()
    }
}

// IPRateLimiter provides IP-based rate limiting with configurable limits.
type IPRateLimiter struct {
    limiter *RateLimiter
}

// NewIPRateLimiter creates a rate limiter for IP addresses.
// Defaults to 20 requests per minute per IP if not specified.
func NewIPRateLimiter(requestsPerMinute int) *IPRateLimiter {
    if requestsPerMinute <= 0 {
        requestsPerMinute = 20
    }
    return &IPRateLimiter{
        limiter: NewRateLimiter(time.Minute, requestsPerMinute),
    }
}

// Allow checks if a request from the given IP is allowed.
func (r *IPRateLimiter) Allow(ip string) bool {
    return r.limiter.Allow("ip:" + ip)
}

// EmailRateLimiter provides email-based rate limiting.
type EmailRateLimiter struct {
    limiter *RateLimiter
}

// NewEmailRateLimiter creates a rate limiter for email addresses.
// Uses the configured limit per hour.
func NewEmailRateLimiter(requestsPerHour int) *EmailRateLimiter {
    if requestsPerHour <= 0 {
        requestsPerHour = 5
    }
    return &EmailRateLimiter{
        limiter: NewRateLimiter(time.Hour, requestsPerHour),
    }
}

// Allow checks if a magic link request for the given email is allowed.
func (r *EmailRateLimiter) Allow(email string) bool {
    return r.limiter.Allow("email:" + email)
}
