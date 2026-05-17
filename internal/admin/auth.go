package admin

import (
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// AuthMiddleware provides token-based authentication for admin API endpoints.
// If no token is configured, all requests are allowed.
type AuthMiddleware struct {
	token         string
	publicPaths   map[string]bool // paths that don't require auth
	allowedSources []net.IPNet    // IP ranges allowed to access admin API
}

// NewAuthMiddleware creates an auth middleware with the given bearer token.
func NewAuthMiddleware(token string) *AuthMiddleware {
	return &AuthMiddleware{
		token: token,
		publicPaths: map[string]bool{
			"/healthz": true,
			"/livez":   true,
			"/ready":   true,
			"/readyz":  true,
			"/metrics": true,
		},
	}
}

// WithAllowedSources sets IP ranges that are allowed to access admin API.
// If not set, all IPs are allowed (after auth).
func (a *AuthMiddleware) WithAllowedSources(sources []string) *AuthMiddleware {
	for _, s := range sources {
		if _, ipnet, err := net.ParseCIDR(s); err == nil {
			a.allowedSources = append(a.allowedSources, *ipnet)
		}
	}
	return a
}

func (a *AuthMiddleware) isIPAllowed(ip net.IP) bool {
	if len(a.allowedSources) == 0 {
		return true // no restriction
	}
	for _, allowed := range a.allowedSources {
		if allowed.Contains(ip) {
			return true
		}
	}
	return false
}

// Wrap wraps an http.Handler with authentication.
func (a *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	if a.token == "" {
		return next // no auth configured
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for public paths
		if a.publicPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}

		// Check Authorization header
		auth := r.Header.Get("Authorization")
		if auth == "" {
			// DEPRECATED: Query parameter auth is only for WebSocket convenience.
			// Tokens in URLs are logged, cached, and exposed in Referrer headers.
			// Prefer using Authorization header instead.
			if qToken := r.URL.Query().Get("token"); qToken != "" {
				slog.Warn("query string token auth is deprecated", "path", r.URL.Path)
				auth = "Bearer " + qToken
			}
		}

		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		providedToken := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(providedToken), []byte(a.token)) != 1 {
			http.Error(w, `{"error":"invalid token"}`, http.StatusForbidden)
			return
		}

		// Check IP allowlist
		clientIP := getClientIP(r)
		if !a.isIPAllowed(clientIP) {
			slog.Warn("admin API access denied", "ip", clientIP.String(), "path", r.URL.Path)
			http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func getClientIP(r *http.Request) net.IP {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			xff = xff[:idx]
		}
		if ip := net.ParseIP(strings.TrimSpace(xff)); ip != nil {
			return ip
		}
	}
	// Fall back to X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return ip
		}
	}
	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}
