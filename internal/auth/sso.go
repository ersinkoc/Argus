package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SSOConfig configures SSO/JWT token authentication.
type SSOConfig struct {
	Issuer       string   `json:"issuer"`        // expected JWT issuer
	Secret       string   `json:"secret"`        // HMAC secret for validation
	UsernameClaim string  `json:"username_claim"` // JWT claim for username (default: "sub")
	GroupsClaim   string  `json:"groups_claim"`   // JWT claim for groups (default: "groups")
	AllowedIssuers []string `json:"allowed_issuers"` // allowed issuers
}

// SSOProvider validates JWT tokens from SSO systems.
type SSOProvider struct {
	cfg SSOConfig
}

// JWTClaims represents parsed JWT claims.
type JWTClaims struct {
	Subject  string   `json:"sub"`
	Issuer   string   `json:"iss"`
	Audience string   `json:"aud"`
	Expiry   int64    `json:"exp"`
	IssuedAt int64    `json:"iat"`
	Username string   `json:"preferred_username,omitempty"`
	Email    string   `json:"email,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

// NewSSOProvider creates an SSO auth provider.
func NewSSOProvider(cfg SSOConfig) *SSOProvider {
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "sub"
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	return &SSOProvider{cfg: cfg}
}

// ValidateToken validates a JWT token and returns user info.
func (p *SSOProvider) ValidateToken(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Verify signature (HMAC-SHA256)
	if p.cfg.Secret != "" {
		signatureInput := parts[0] + "." + parts[1]
		expectedSig := hmacSHA256([]byte(p.cfg.Secret), []byte(signatureInput))
		actualSig, err := base64URLDecode(parts[2])
		if err != nil {
			return nil, fmt.Errorf("invalid JWT signature encoding: %w", err)
		}
		if !hmac.Equal(expectedSig, actualSig) {
			return nil, fmt.Errorf("JWT signature verification failed")
		}
	}

	// Decode payload
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims: %w", err)
	}

	// Verify expiry
	if claims.Expiry > 0 && time.Now().Unix() > claims.Expiry {
		return nil, fmt.Errorf("JWT token expired")
	}

	// Verify issuer
	if p.cfg.Issuer != "" && claims.Issuer != p.cfg.Issuer {
		return nil, fmt.Errorf("JWT issuer mismatch: got %q, want %q", claims.Issuer, p.cfg.Issuer)
	}

	return &claims, nil
}

// ExtractUsername returns the username from JWT claims based on config.
func (p *SSOProvider) ExtractUsername(claims *JWTClaims) string {
	switch p.cfg.UsernameClaim {
	case "sub":
		return claims.Subject
	case "email":
		return claims.Email
	case "preferred_username":
		return claims.Username
	default:
		return claims.Subject
	}
}

// ExtractGroups returns groups from JWT claims.
func (p *SSOProvider) ExtractGroups(claims *JWTClaims) []string {
	if len(claims.Groups) > 0 {
		return claims.Groups
	}
	return claims.Roles
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
