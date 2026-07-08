package gateway

import (
	"crypto/subtle"
	"net/http"
	"sync"
)

// APIKey represents a gateway API key with associated identity.
type APIKey struct {
	Key       string   `json:"key"`
	Username  string   `json:"username"`
	Roles     []string `json:"roles,omitempty"`
	Database  string   `json:"database,omitempty"`
	RateLimit float64  `json:"rate_limit,omitempty"`
	Enabled   bool     `json:"enabled"`
}

// APIKeyStore manages gateway API keys.
type APIKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*APIKey // key string -> APIKey
}

// NewAPIKeyStore creates an API key store from config.
func NewAPIKeyStore() *APIKeyStore {
	return &APIKeyStore{
		keys: make(map[string]*APIKey),
	}
}

// Add registers an API key.
func (s *APIKeyStore) Add(key *APIKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.Key] = key
}

// Validate checks an API key and returns the associated identity.
// Uses constant-time comparison to prevent timing attacks.
func (s *APIKeyStore) Validate(key string) *APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Use constant-time comparison to prevent timing attacks
	for _, k := range s.keys {
		if k.Enabled && subtle.ConstantTimeCompare([]byte(k.Key), []byte(key)) == 1 {
			return k
		}
	}
	return nil
}

// Count returns the number of registered keys.
func (s *APIKeyStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}

// Middleware returns HTTP middleware that validates X-API-Key headers
// and injects the resolved APIKey into the request context.
func (s *APIKeyStore) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			http.Error(w, `{"error":"missing API key"}`, http.StatusUnauthorized)
			return
		}

		key := s.Validate(apiKey)
		if key == nil {
			http.Error(w, `{"error":"invalid API key"}`, http.StatusForbidden)
			return
		}

		ctx := ContextWithAPIKey(r.Context(), key)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
