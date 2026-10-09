package api

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName = "sniffd_session"
	sessionLifetime   = 12 * time.Hour
	loginWindow       = time.Minute
	maxLoginFailures  = 5
)

type loginAttempt struct {
	windowStart time.Time
	failures    int
}

type authenticator struct {
	token    []byte
	mu       sync.Mutex
	attempts map[string]loginAttempt
}

func newAuthenticator(token string) *authenticator {
	return &authenticator{token: []byte(token), attempts: make(map[string]loginAttempt)}
}

func (a *authenticator) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	address := clientAddress(r)
	if a.rateLimited(address, time.Now()) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var request struct {
		Token string `json:"token"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(request.Token), a.token) != 1 {
		a.recordFailure(address, time.Now())
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	a.clearFailures(address)
	value, err := a.newSession(time.Now().Add(sessionLifetime))
	if err != nil {
		http.Error(w, "unable to create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: value, Path: "/", MaxAge: int(sessionLifetime.Seconds()), HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (a *authenticator) logout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (a *authenticator) session(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]bool{"authenticated": a.authenticated(r)})
}

func (a *authenticator) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.authenticated(r) {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *authenticator) authenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 {
		return false
	}
	expires, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() >= expires {
		return false
	}
	message := parts[0] + "." + parts[1]
	expected := a.sign(message)
	provided, err := base64.RawURLEncoding.DecodeString(parts[2])
	return err == nil && hmac.Equal(provided, expected)
}

func (a *authenticator) newSession(expires time.Time) (string, error) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	message := strconv.FormatInt(expires.Unix(), 10) + "." + base64.RawURLEncoding.EncodeToString(nonce)
	return message + "." + base64.RawURLEncoding.EncodeToString(a.sign(message)), nil
}

func (a *authenticator) sign(message string) []byte {
	mac := hmac.New(sha256.New, a.token)
	_, _ = mac.Write([]byte(message))
	return mac.Sum(nil)
}

func (a *authenticator) rateLimited(address string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	attempt := a.attempts[address]
	if now.Sub(attempt.windowStart) >= loginWindow {
		delete(a.attempts, address)
		return false
	}
	return attempt.failures >= maxLoginFailures
}

func (a *authenticator) recordFailure(address string, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	attempt := a.attempts[address]
	if attempt.windowStart.IsZero() || now.Sub(attempt.windowStart) >= loginWindow {
		attempt = loginAttempt{windowStart: now}
	}
	attempt.failures++
	a.attempts[address] = attempt
}

func (a *authenticator) clearFailures(address string) {
	a.mu.Lock()
	delete(a.attempts, address)
	a.mu.Unlock()
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
