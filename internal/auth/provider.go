package auth

// IdentityProvider is the interface for external identity providers.
type IdentityProvider interface {
	// Name returns the provider name.
	Name() string

	// Authenticate verifies credentials and returns groups/roles.
	Authenticate(username, password string) (groups []string, err error)
}

// IdentityResult holds the result of identity resolution.
type IdentityResult struct {
	Username string
	Groups   []string
	Roles    []string
	Provider string // which provider authenticated ("ldap", "sso", "local")
	Metadata map[string]string
}

// ChainProvider tries multiple identity providers in order.
type ChainProvider struct {
	providers []IdentityProvider
}

// NewChainProvider creates a chain of identity providers.
func NewChainProvider(providers ...IdentityProvider) *ChainProvider {
	return &ChainProvider{providers: providers}
}

// Authenticate tries each provider until one succeeds.
func (c *ChainProvider) Authenticate(username, password string) (*IdentityResult, error) {
	var lastErr error

	for _, p := range c.providers {
		groups, err := p.Authenticate(username, password)
		if err == nil {
			return &IdentityResult{
				Username: username,
				Groups:   groups,
				Provider: p.Name(),
			}, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}

// LDAPProvider implements IdentityProvider.
func (p *LDAPProvider) Name() string { return "ldap" }
