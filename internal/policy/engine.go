package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ersinkoc/argus/internal/metrics"
)

// Engine is the policy evaluation engine.
type Engine struct {
	loader *Loader
	cache  *decisionCache
}

// NewEngine creates a new policy engine.
func NewEngine(loader *Loader) *Engine {
	e := &Engine{
		loader: loader,
		cache:  newDecisionCache(10000, 60*time.Second),
	}
	return e
}

// Loader returns the policy loader.
func (e *Engine) Loader() *Loader {
	return e.loader
}

// Evaluate evaluates a context against loaded policies.
func (e *Engine) Evaluate(ctx *Context) *Decision {
	ps := e.loader.Current()
	if ps == nil {
		return &Decision{
			Action:     ActionBlock,
			Reason:     "no policies loaded — fail-closed",
			PolicyName: "default",
			LogLevel:   "standard",
		}
	}

	// Check cache
	cacheKey := e.cacheKey(ctx)
	if d, ok := e.cache.get(cacheKey); ok {
		metrics.Global.PolicyCacheHits.Add(1)
		return d
	}

	decision := e.evaluate(ctx, ps)

	// Cache the decision
	e.cache.set(cacheKey, decision)
	metrics.Global.PolicyCacheMisses.Add(1)

	return decision
}

// InvalidateCache clears the decision cache and regex cache (called on policy reload).
func (e *Engine) InvalidateCache() {
	e.cache.clear()
	ClearRegexCache()
}

func (e *Engine) evaluate(ctx *Context, ps *PolicySet) *Decision {
	// Resolve user roles
	ctx.Roles = ResolveUserRoles(ctx.Username, ps.Roles)

	// Evaluate policies top-to-bottom, first match wins
	var maskingRules []MaskingRule

	for _, rule := range ps.Policies {
		if !e.matchRule(ctx, &rule, ps.Roles) {
			continue
		}

		// Rule matched
		decision := &Decision{
			PolicyName: rule.Name,
			Reason:     rule.Reason,
			LogLevel:   rule.LogLevel,
			MaxRows:    rule.MaxRows,
			RateLimit:  rule.RateLimit,
		}

		if rule.Action != "" {
			decision.Action = ParseAction(rule.Action)
		}

		// Masking rules are cumulative
		if len(rule.Masking) > 0 {
			maskingRules = append(maskingRules, rule.Masking...)
			if decision.Action == ActionAllow {
				decision.Action = ActionMask
			}
		}

		decision.MaskingRules = maskingRules

		// Calculate risk score
		decision.RiskScore = int(ctx.RiskLevel) * 25

		if decision.LogLevel == "" {
			decision.LogLevel = ps.Defaults.LogLevel
		}

		return decision
	}

	// No policy matched, use defaults
	return &Decision{
		Action:       ParseAction(ps.Defaults.Action),
		Reason:       "default policy",
		PolicyName:   "default",
		LogLevel:     ps.Defaults.LogLevel,
		MaxRows:      ps.Defaults.MaxRows,
		MaskingRules: maskingRules,
	}
}

func (e *Engine) matchRule(ctx *Context, rule *PolicyRule, roles map[string]Role) bool {
	// Match roles
	if !matchRole(ctx, rule.Match.Roles, roles) {
		return false
	}

	// Match commands
	if !matchCommands(ctx.CommandType, rule.Match.Commands) {
		return false
	}

	// Match databases
	if !matchDatabases(ctx.Database, rule.Match.Databases) {
		return false
	}

	// Match tables
	if !matchTables(ctx.Tables, rule.Match.Tables) {
		return false
	}

	// Match conditions
	if !matchCondition(ctx, rule.Condition) {
		return false
	}

	return true
}

func (e *Engine) cacheKey(ctx *Context) string {
	// Cache key must include all fields that condition matchers inspect.
	// Omitting any field would cause cache hits to bypass those conditions.
	ipStr := ""
	if ctx.ClientIP != nil {
		ipStr = ctx.ClientIP.String()
	}
	hasWhere := "0"
	if ctx.HasWhere {
		hasWhere = "1"
	}
	key := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%d|%f",
		ctx.Username,
		strings.Join(ctx.Roles, ","),
		ctx.Database,
		ctx.CommandType.String(),
		strings.Join(ctx.Tables, ","),
		ipStr,
		hasWhere,
		ctx.CostScore,
		ctx.PlanCost,
	)
	// Include RawSQL hash separately (SQL can be very long)
	sqlHash := sha256.Sum256([]byte(ctx.RawSQL))
	combined := key + "|" + hex.EncodeToString(sqlHash[:8])
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:16])
}

// decisionCache is a bounded LRU-like cache for policy decisions.
type decisionCache struct {
	entries map[string]*cacheEntry
	mu      sync.RWMutex
	maxSize int
	ttl     time.Duration
}

type cacheEntry struct {
	decision *Decision
	expiry   time.Time
}

func newDecisionCache(maxSize int, ttl time.Duration) *decisionCache {
	return &decisionCache{
		entries: make(map[string]*cacheEntry, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func (c *decisionCache) get(key string) (*Decision, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiry) {
		return nil, false
	}
	return entry.decision, true
}

func (c *decisionCache) set(key string, d *Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if full (simple: clear half)
	if len(c.entries) >= c.maxSize {
		count := 0
		for k := range c.entries {
			delete(c.entries, k)
			count++
			if count >= c.maxSize/2 {
				break
			}
		}
	}

	c.entries[key] = &cacheEntry{
		decision: d,
		expiry:   time.Now().Add(c.ttl),
	}
}

func (c *decisionCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheEntry, c.maxSize)
}
