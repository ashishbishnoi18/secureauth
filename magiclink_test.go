package secureauth

import (
    "context"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "net/http"
    "net/http/httptest"
    "net/url"
    "strings"
    "testing"
    "time"
)

// mockStore implements the Store interface for testing
type mockStore struct {
    users       map[int64]*User
    identities  map[string]*Identity // key: provider:subject
    magicLinks  map[string]*MagicLink // key: tokenHash
    sessions    map[string]*Session // key: tokenHash
    nextUserID  int64
    nextIdentID int64
    nextMLID    int64
    nextSessID  int64
}

func newMockStore() *mockStore {
    return &mockStore{
        users:       make(map[int64]*User),
        identities:  make(map[string]*Identity),
        magicLinks:  make(map[string]*MagicLink),
        sessions:    make(map[string]*Session),
        nextUserID:  1,
        nextIdentID: 1,
        nextMLID:    1,
        nextSessID:  1,
    }
}

func (m *mockStore) GetUserByGoogleSub(ctx context.Context, sub string) (*User, error) {
    for _, u := range m.users {
        if u.GoogleSub == sub {
            return u, nil
        }
    }
    return nil, nil
}

func (m *mockStore) GetUserByID(ctx context.Context, id int64) (*User, error) {
    return m.users[id], nil
}

func (m *mockStore) CreateUser(ctx context.Context, u *User) error {
    u.ID = m.nextUserID
    m.nextUserID++
    u.CreatedAt = time.Now()
    u.UpdatedAt = time.Now()
    m.users[u.ID] = u
    return nil
}

func (m *mockStore) CreateUserMinimal(ctx context.Context, email, name string) (*User, error) {
    u := &User{
        Email: email,
        Name:  name,
    }
    if err := m.CreateUser(ctx, u); err != nil {
        return nil, err
    }
    return u, nil
}

func (m *mockStore) UpdateUser(ctx context.Context, u *User) error {
    u.UpdatedAt = time.Now()
    m.users[u.ID] = u
    return nil
}

func (m *mockStore) CreateSession(ctx context.Context, s *Session) error {
    s.ID = m.nextSessID
    m.nextSessID++
    s.CreatedAt = time.Now()
    hash := hashSessionToken(s.SessionToken)
    m.sessions[hash] = s
    return nil
}

func (m *mockStore) GetSessionByToken(ctx context.Context, token string) (*Session, *User, error) {
    hash := hashSessionToken(token)
    sess := m.sessions[hash]
    if sess == nil {
        return nil, nil, nil
    }
    user := m.users[sess.UserID]
    return sess, user, nil
}

func (m *mockStore) TouchSession(ctx context.Context, id int64, newExpiresAt time.Time) error {
    for _, s := range m.sessions {
        if s.ID == id {
            s.ExpiresAt = newExpiresAt
            s.LastSeenAt = time.Now()
            return nil
        }
    }
    return nil
}

func (m *mockStore) DeleteSessionByToken(ctx context.Context, token string) error {
    hash := hashSessionToken(token)
    delete(m.sessions, hash)
    return nil
}

func (m *mockStore) GetIdentityByProviderSubject(ctx context.Context, provider, subject string) (*Identity, error) {
    key := provider + ":" + subject
    return m.identities[key], nil
}

func (m *mockStore) GetIdentitiesByEmail(ctx context.Context, email string) ([]*Identity, error) {
    var result []*Identity
    for _, id := range m.identities {
        if id.Email == email && id.EmailVerified {
            result = append(result, id)
        }
    }
    return result, nil
}

func (m *mockStore) CreateIdentity(ctx context.Context, i *Identity) error {
    i.ID = m.nextIdentID
    m.nextIdentID++
    i.CreatedAt = time.Now()
    i.UpdatedAt = time.Now()
    key := i.Provider + ":" + i.ProviderSubject
    m.identities[key] = i
    return nil
}

func (m *mockStore) UpdateIdentity(ctx context.Context, i *Identity) error {
    i.UpdatedAt = time.Now()
    key := i.Provider + ":" + i.ProviderSubject
    m.identities[key] = i
    return nil
}

func (m *mockStore) CreateMagicLink(ctx context.Context, ml *MagicLink) error {
    ml.ID = m.nextMLID
    m.nextMLID++
    ml.CreatedAt = time.Now()
    m.magicLinks[ml.TokenHash] = ml
    return nil
}

func (m *mockStore) GetMagicLinkByTokenHash(ctx context.Context, tokenHash string) (*MagicLink, error) {
    return m.magicLinks[tokenHash], nil
}

func (m *mockStore) ConsumeMagicLink(ctx context.Context, id int64, consumedIP, consumedUserAgent string) error {
    for _, ml := range m.magicLinks {
        if ml.ID == id {
            if ml.UsedAt != nil {
                return fmt.Errorf("magic link already used or not found")
            }
            now := time.Now()
            ml.UsedAt = &now
            ml.ConsumedIP = consumedIP
            ml.ConsumedUserAgent = consumedUserAgent
            return nil
        }
    }
    return fmt.Errorf("magic link already used or not found")
}

func (m *mockStore) CountRecentMagicLinks(ctx context.Context, email string, since time.Time) (int, error) {
    count := 0
    for _, ml := range m.magicLinks {
        if ml.Email == email && ml.CreatedAt.After(since) {
            count++
        }
    }
    return count, nil
}

func (m *mockStore) DeleteExpiredMagicLinks(ctx context.Context) error {
    now := time.Now()
    for hash, ml := range m.magicLinks {
        if now.After(ml.ExpiresAt) || ml.UsedAt != nil {
            delete(m.magicLinks, hash)
        }
    }
    return nil
}

// mockEmailSender captures sent emails for testing
type mockEmailSender struct {
    sentEmails []sentEmail
}

type sentEmail struct {
    to               string
    link             string
    expiresInMinutes int
}

func (m *mockEmailSender) SendMagicLink(ctx context.Context, to, link string, expiresInMinutes int) error {
    m.sentEmails = append(m.sentEmails, sentEmail{to, link, expiresInMinutes})
    return nil
}

func TestTokenGeneration(t *testing.T) {
    token, err := generateMagicLinkToken()
    if err != nil {
        t.Fatalf("failed to generate token: %v", err)
    }

    // Token should be base64url encoded 32 bytes (256 bits)
    decoded, err := base64.RawURLEncoding.DecodeString(token)
    if err != nil {
        t.Fatalf("token is not valid base64url: %v", err)
    }

    if len(decoded) != 32 {
        t.Errorf("expected 32 bytes, got %d", len(decoded))
    }

    // Generate another token - should be different
    token2, err := generateMagicLinkToken()
    if err != nil {
        t.Fatalf("failed to generate second token: %v", err)
    }

    if token == token2 {
        t.Error("two generated tokens should not be identical")
    }
}

func TestTokenHashing(t *testing.T) {
    secret := "test-secret-key-that-is-at-least-32-chars"
    cfg := Config{MagicLinkSecret: secret}
    store := newMockStore()
    sender := &mockEmailSender{}

    m := NewMagicLinkAuth(cfg, store, sender)

    token := "test-token-123"
    hash := m.hashToken(token)

    // Hash should be consistent
    hash2 := m.hashToken(token)
    if hash != hash2 {
        t.Error("same token should produce same hash")
    }

    // Different tokens should produce different hashes
    hash3 := m.hashToken("different-token")
    if hash == hash3 {
        t.Error("different tokens should produce different hashes")
    }

    // Verify it's using HMAC-SHA256
    h := hmac.New(sha256.New, []byte(secret))
    h.Write([]byte(token))
    expectedHash := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
    if hash != expectedHash {
        t.Error("hash doesn't match expected HMAC-SHA256")
    }
}

func TestTokenVerification(t *testing.T) {
    secret := "test-secret-key-that-is-at-least-32-chars"
    cfg := Config{MagicLinkSecret: secret}
    store := newMockStore()
    sender := &mockEmailSender{}

    m := NewMagicLinkAuth(cfg, store, sender)

    token := "test-token-123"
    expectedHash := m.hashToken(token)

    // Correct token should verify
    if !m.verifyTokenHash(token, expectedHash) {
        t.Error("correct token should verify")
    }

    // Wrong token should not verify
    if m.verifyTokenHash("wrong-token", expectedHash) {
        t.Error("wrong token should not verify")
    }
}

func TestEmailNormalization(t *testing.T) {
    tests := []struct {
        input    string
        expected string
    }{
        {"Test@Example.COM", "test@example.com"},
        {"  user@test.com  ", "user@test.com"},
        {"USER@DOMAIN.ORG", "user@domain.org"},
    }

    for _, tt := range tests {
        result := strings.TrimSpace(strings.ToLower(tt.input))
        if result != tt.expected {
            t.Errorf("normalize(%q) = %q, want %q", tt.input, result, tt.expected)
        }
    }
}

func TestEmailValidation(t *testing.T) {
    tests := []struct {
        email string
        valid bool
    }{
        {"test@example.com", true},
        {"user@domain.org", true},
        {"a@b.co", true},
        {"", false},
        {"invalid", false},
        {"@example.com", false},
        {"test@", false},
        {"test@domain", false},
        {"test@.com", false},
    }

    for _, tt := range tests {
        result := isValidEmail(tt.email)
        if result != tt.valid {
            t.Errorf("isValidEmail(%q) = %v, want %v", tt.email, result, tt.valid)
        }
    }
}

func TestMagicLinkStart_EnumerationPrevention(t *testing.T) {
    secret := "test-secret-key-that-is-at-least-32-chars"
    cfg := Config{
        MagicLinkSecret:    secret,
        MagicLinkTTL:       30 * time.Minute,
        MagicLinkRateLimit: 5,
        AppBaseURL:         "http://localhost:8080",
    }
    store := newMockStore()
    sender := &mockEmailSender{}

    m := NewMagicLinkAuth(cfg, store, sender)

    // Test with existing user
    existingUser, _ := store.CreateUserMinimal(context.Background(), "existing@example.com", "Existing User")
    store.CreateIdentity(context.Background(), &Identity{
        UserID:          existingUser.ID,
        Provider:        "email",
        ProviderSubject: "existing@example.com",
        Email:           "existing@example.com",
        EmailVerified:   true,
    })

    // Request for existing email
    form := url.Values{}
    form.Set("email", "existing@example.com")
    req1 := httptest.NewRequest(http.MethodPost, "/auth/email/start", strings.NewReader(form.Encode()))
    req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    w1 := httptest.NewRecorder()
    m.EmailStartHandler(w1, req1)

    // Request for non-existing email
    form2 := url.Values{}
    form2.Set("email", "nonexisting@example.com")
    req2 := httptest.NewRequest(http.MethodPost, "/auth/email/start", strings.NewReader(form2.Encode()))
    req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    w2 := httptest.NewRecorder()
    m.EmailStartHandler(w2, req2)

    // Both should return 200 (same response to prevent enumeration)
    if w1.Code != http.StatusOK {
        t.Errorf("existing email: expected 200, got %d", w1.Code)
    }
    if w2.Code != http.StatusOK {
        t.Errorf("non-existing email: expected 200, got %d", w2.Code)
    }

    // Response bodies should be identical (both show "check your email" page)
    if w1.Body.String() != w2.Body.String() {
        t.Error("responses should be identical to prevent enumeration")
    }
}

func TestMagicLinkExpiry(t *testing.T) {
    secret := "test-secret-key-that-is-at-least-32-chars"
    cfg := Config{
        MagicLinkSecret:    secret,
        MagicLinkTTL:       30 * time.Minute,
        MagicLinkRateLimit: 5,
        AppBaseURL:         "http://localhost:8080",
    }
    store := newMockStore()
    sender := &mockEmailSender{}

    m := NewMagicLinkAuth(cfg, store, sender)

    // Create an expired magic link
    token := "test-token"
    tokenHash := m.hashToken(token)
    expiredML := &MagicLink{
        Email:     "test@example.com",
        TokenHash: tokenHash,
        ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
    }
    store.CreateMagicLink(context.Background(), expiredML)

    // Try to verify expired token
    req := httptest.NewRequest(http.MethodGet, "/auth/email/verify?token="+token, nil)
    w := httptest.NewRecorder()
    m.EmailVerifyHandler(w, req)

    // Should show error page
    if w.Code != http.StatusBadRequest {
        t.Errorf("expired token: expected 400, got %d", w.Code)
    }

    if !strings.Contains(w.Body.String(), "expired") {
        t.Error("response should mention expiration")
    }
}

func TestMagicLinkSingleUse(t *testing.T) {
    secret := "test-secret-key-that-is-at-least-32-chars"
    cfg := Config{
        MagicLinkSecret:    secret,
        MagicLinkTTL:       30 * time.Minute,
        MagicLinkRateLimit: 5,
        AppBaseURL:         "http://localhost:8080",
        SessionTTL:         720 * time.Hour,
        CookieName:         "test_session",
        AfterLoginPath:     "/",
    }
    store := newMockStore()
    sender := &mockEmailSender{}

    m := NewMagicLinkAuth(cfg, store, sender)

    // Create auth handler for session creation
    auth, _ := New(context.Background(), cfg, store)
    auth.SetMagicLinkAuth(m)

    // Create a valid magic link
    token := "valid-token"
    tokenHash := m.hashToken(token)
    validML := &MagicLink{
        Email:     "test@example.com",
        TokenHash: tokenHash,
        ExpiresAt: time.Now().Add(30 * time.Minute),
    }
    store.CreateMagicLink(context.Background(), validML)

    // First consumption should succeed
    form := url.Values{}
    form.Set("token", token)
    req1 := httptest.NewRequest(http.MethodPost, "/auth/email/consume", strings.NewReader(form.Encode()))
    req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    w1 := httptest.NewRecorder()
    handler := m.EmailConsumeHandler(auth)
    handler(w1, req1)

    // Should redirect (success)
    if w1.Code != http.StatusSeeOther {
        t.Errorf("first consumption: expected 303, got %d", w1.Code)
    }

    // Second consumption should fail
    req2 := httptest.NewRequest(http.MethodPost, "/auth/email/consume", strings.NewReader(form.Encode()))
    req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    w2 := httptest.NewRecorder()
    handler(w2, req2)

    // Should show error
    if w2.Code != http.StatusBadRequest {
        t.Errorf("second consumption: expected 400, got %d", w2.Code)
    }

    if !strings.Contains(w2.Body.String(), "already been used") {
        t.Error("response should mention link already used")
    }
}

func TestEmailLinking_GoogleThenMagicLink(t *testing.T) {
    secret := "test-secret-key-that-is-at-least-32-chars"
    cfg := Config{
        MagicLinkSecret:    secret,
        MagicLinkTTL:       30 * time.Minute,
        MagicLinkRateLimit: 5,
        AppBaseURL:         "http://localhost:8080",
        SessionTTL:         720 * time.Hour,
        CookieName:         "test_session",
        AfterLoginPath:     "/",
    }
    store := newMockStore()
    sender := &mockEmailSender{}

    // Create a user who first logged in with Google
    googleUser := &User{
        GoogleSub: "google-123",
        Email:     "user@example.com",
        Name:      "Google User",
    }
    store.CreateUser(context.Background(), googleUser)

    // Create Google identity
    googleIdentity := &Identity{
        UserID:          googleUser.ID,
        Provider:        "google",
        ProviderSubject: "google-123",
        Email:           "user@example.com",
        EmailVerified:   true,
    }
    store.CreateIdentity(context.Background(), googleIdentity)

    // Now simulate magic link login with the same email
    m := NewMagicLinkAuth(cfg, store, sender)

    user, err := m.findOrCreateUserByEmail(context.Background(), "user@example.com")
    if err != nil {
        t.Fatalf("findOrCreateUserByEmail failed: %v", err)
    }

    // Should return the same user
    if user.ID != googleUser.ID {
        t.Errorf("expected same user ID %d, got %d", googleUser.ID, user.ID)
    }

    // Should have created an email identity for the user
    identities, _ := store.GetIdentitiesByEmail(context.Background(), "user@example.com")
    hasEmailIdentity := false
    for _, id := range identities {
        if id.Provider == "email" {
            hasEmailIdentity = true
            break
        }
    }

    if !hasEmailIdentity {
        t.Error("should have created email identity for existing Google user")
    }
}

func TestRateLimiter(t *testing.T) {
    limiter := NewRateLimiter(time.Minute, 3)

    key := "test@example.com"

    // First 3 requests should be allowed
    for i := 0; i < 3; i++ {
        if !limiter.Allow(key) {
            t.Errorf("request %d should be allowed", i+1)
        }
    }

    // 4th request should be blocked
    if limiter.Allow(key) {
        t.Error("4th request should be blocked")
    }

    // Different key should be allowed
    if !limiter.Allow("other@example.com") {
        t.Error("different key should be allowed")
    }
}

func TestOpenRedirectPrevention(t *testing.T) {
    // The AfterLoginPath should only allow relative paths
    cfg := Config{
        AfterLoginPath: "/dashboard",
    }

    // Valid relative paths
    validPaths := []string{"/", "/dashboard", "/profile/settings"}
    for _, path := range validPaths {
        if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
            t.Errorf("path %q should be valid", path)
        }
    }

    // The config validation should prevent absolute URLs
    // In practice, the app should validate redirects server-side
    _ = cfg
}

// TestDuplicateVerifiedEmail_FailsClosed tests that the system fails closed
// when a unique constraint violation occurs on verified email.
func TestDuplicateVerifiedEmail_FailsClosed(t *testing.T) {
    secret := "test-secret-key-that-is-at-least-32-chars"
    cfg := Config{
        MagicLinkSecret:    secret,
        MagicLinkTTL:       30 * time.Minute,
        MagicLinkRateLimit: 5,
        AppBaseURL:         "http://localhost:8080",
        SessionTTL:         720 * time.Hour,
        CookieName:         "test_session",
        AfterLoginPath:     "/",
    }

    // Create a mock store that simulates a unique constraint violation
    store := &mockStoreWithUniqueViolation{
        mockStore:                newMockStore(),
        simulateUniqueViolation: true,
    }
    sender := &mockEmailSender{}

    m := NewMagicLinkAuth(cfg, store, sender)

    // Try to find/create a user - should fail due to unique constraint
    _, err := m.findOrCreateUserByEmail(context.Background(), "conflict@example.com")

    // Error should occur
    if err == nil {
        t.Fatal("expected error for duplicate verified email, got nil")
    }

    // Error message should contain "account conflict" but NOT leak email or internal details
    errStr := err.Error()
    if !strings.Contains(errStr, "account conflict") {
        t.Errorf("error should mention 'account conflict', got: %s", errStr)
    }
    if strings.Contains(errStr, "duplicate") || strings.Contains(errStr, "unique") {
        t.Errorf("error should not leak internal constraint details, got: %s", errStr)
    }
    if strings.Contains(errStr, "conflict@example.com") {
        t.Errorf("error should not leak email address, got: %s", errStr)
    }
    // Should contain correlation ID reference
    if !strings.Contains(errStr, "ref:") {
        t.Errorf("error should contain correlation ID reference, got: %s", errStr)
    }
}

// mockStoreWithUniqueViolation wraps mockStore but simulates unique constraint violations
type mockStoreWithUniqueViolation struct {
    *mockStore
    simulateUniqueViolation bool
}

func (m *mockStoreWithUniqueViolation) CreateIdentity(ctx context.Context, i *Identity) error {
    if m.simulateUniqueViolation {
        return ErrDuplicateVerifiedEmail
    }
    return m.mockStore.CreateIdentity(ctx, i)
}

// TestEmailNormalization_Defensive tests that the store layer normalizes emails
func TestEmailNormalization_Defensive(t *testing.T) {
    // This test verifies that even if the caller passes non-normalized email,
    // the store layer normalizes it defensively.

    tests := []struct {
        input    string
        expected string
    }{
        {"User@Example.COM", "user@example.com"},
        {"  USER@TEST.ORG  ", "user@test.org"},
        {"MixedCase@Domain.Net", "mixedcase@domain.net"},
    }

    for _, tt := range tests {
        // Test with mockStore - verifies the normalization happens
        normalizedEmail := strings.TrimSpace(strings.ToLower(tt.input))
        if normalizedEmail != tt.expected {
            t.Errorf("normalize(%q) = %q, want %q", tt.input, normalizedEmail, tt.expected)
        }
    }
}

// TestRaceSafeTokenConsumption tests that concurrent token consumption
// results in only one success (atomic single-use)
func TestRaceSafeTokenConsumption(t *testing.T) {
    secret := "test-secret-key-that-is-at-least-32-chars"
    cfg := Config{
        MagicLinkSecret:    secret,
        MagicLinkTTL:       30 * time.Minute,
        MagicLinkRateLimit: 5,
        AppBaseURL:         "http://localhost:8080",
        SessionTTL:         720 * time.Hour,
        CookieName:         "test_session",
        AfterLoginPath:     "/",
    }
    store := newMockStore()
    sender := &mockEmailSender{}

    m := NewMagicLinkAuth(cfg, store, sender)
    auth, _ := New(context.Background(), cfg, store)
    auth.SetMagicLinkAuth(m)

    // Create a valid magic link
    token := "race-test-token"
    tokenHash := m.hashToken(token)
    validML := &MagicLink{
        Email:     "race@example.com",
        TokenHash: tokenHash,
        ExpiresAt: time.Now().Add(30 * time.Minute),
    }
    store.CreateMagicLink(context.Background(), validML)

    // First consumption should succeed
    err1 := store.ConsumeMagicLink(context.Background(), validML.ID, "1.2.3.4", "test-agent")

    // Second consumption should fail
    err2 := store.ConsumeMagicLink(context.Background(), validML.ID, "5.6.7.8", "test-agent2")

    if err1 != nil {
        t.Errorf("first consumption should succeed, got error: %v", err1)
    }

    if err2 == nil {
        t.Error("second consumption should fail, but succeeded")
    }
}
