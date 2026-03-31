package gateway

import (
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
// Returns nil if invalid or disabled.
func (s *APIKeyStore) Validate(key string) *APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	k, ok := s.keys[key]
	if !ok || !k.Enabled {
		return nil
	}
	return k
}

// Count returns the number of registered keys.
func (s *APIKeyStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.keys)
}

// Middleware returns HTTP middleware that validates X-API-Key headers
// and injects the resolved APIKey into the request context.
// Falls through to the next handler if no X-API-Key is present
// (allowing admin bearer token auth to handle it).
func (s *APIKeyStore) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// No API key — fall through to bearer token auth
			next.ServeHTTP(w, r)
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
