package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
)

// APIKey represents a gateway API key with associated identity.
type APIKey struct {
	ID           string   `json:"id,omitempty"`
	Key          string   `json:"key"`
	PreviousKeys []string `json:"previous_keys,omitempty"`
	Fingerprint  string   `json:"fingerprint,omitempty"`
	Username     string   `json:"username"`
	Roles        []string `json:"roles,omitempty"`
	Database     string   `json:"database,omitempty"`
	RateLimit    float64  `json:"rate_limit,omitempty"`
	Enabled      bool     `json:"enabled"`
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
	key.ensureMetadata()
	s.keys[key.Key] = key
}

func (k *APIKey) ensureMetadata() {
	if k.ID == "" {
		k.ID = keyFingerprint(k.Key)
	}
	if k.Fingerprint == "" {
		k.Fingerprint = keyFingerprint(k.Key)
	}
}

func keyFingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:6])
}

func (k *APIKey) matches(candidate string) bool {
	if subtle.ConstantTimeCompare([]byte(k.Key), []byte(candidate)) == 1 {
		return true
	}
	for _, previous := range k.PreviousKeys {
		if subtle.ConstantTimeCompare([]byte(previous), []byte(candidate)) == 1 {
			return true
		}
	}
	return false
}

// Validate checks an API key and returns the associated identity.
// Uses constant-time comparison to prevent timing attacks.
func (s *APIKeyStore) Validate(key string) *APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, k := range s.keys {
		if k.Enabled && k.matches(key) {
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
			writeAPIError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing API key")
			return
		}

		key := s.Validate(apiKey)
		if key == nil {
			writeAPIError(w, http.StatusForbidden, "FORBIDDEN", "invalid API key")
			return
		}

		ctx := ContextWithAPIKey(r.Context(), key)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
