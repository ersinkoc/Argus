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
	token          string
	publicPaths    map[string]bool // paths that don't require auth
	allowedSources []net.IPNet     // IP ranges allowed to access admin API
	trustedProxies []net.IPNet     // proxy IP ranges whose X-Forwarded-For is trusted
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

// WithTrustedProxies sets IP ranges whose X-Forwarded-For header is trusted.
// If not set, forwarded headers are ignored and only RemoteAddr is used.
func (a *AuthMiddleware) WithTrustedProxies(proxies []string) *AuthMiddleware {
	for _, s := range proxies {
		if _, ipnet, err := net.ParseCIDR(s); err == nil {
			a.trustedProxies = append(a.trustedProxies, *ipnet)
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
		clientIP := a.getClientIP(r)
		if !a.isIPAllowed(clientIP) {
			slog.Warn("admin API access denied", "ip", clientIP.String(), "path", r.URL.Path)
			http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *AuthMiddleware) getClientIP(r *http.Request) net.IP {
	remoteIP := parseRemoteAddr(r.RemoteAddr)

	// Only trust forwarded headers when the immediate connection comes from a trusted proxy
	if a.isTrustedProxy(remoteIP) {
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
	}

	return remoteIP
}

func (a *AuthMiddleware) isTrustedProxy(ip net.IP) bool {
	if len(a.trustedProxies) == 0 {
		return false // no proxies configured — never trust forwarded headers
	}
	for _, p := range a.trustedProxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func parseRemoteAddr(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return net.ParseIP(addr)
	}
	return net.ParseIP(host)
}
