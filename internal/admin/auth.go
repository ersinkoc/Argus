package admin

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// AuthMiddleware provides token-based authentication for admin API endpoints.
// If no token is configured, all requests are allowed.
type AuthMiddleware struct {
	token      string
	publicPaths map[string]bool // paths that don't require auth
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
			// Also check query parameter for WebSocket
			if qToken := r.URL.Query().Get("token"); qToken != "" {
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

		next.ServeHTTP(w, r)
	})
}
