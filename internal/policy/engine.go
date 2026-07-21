package policy

import (
	"container/list"
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
	// Resolve roles from the policy file by username and merge them with any roles the caller already
	// put on the context. In proxy-auth mode the wire username is an opaque handle, so the identity
	// resolver's roles arrive on ctx.Roles (via the session) and must not be discarded here.
	ctx.Roles = unionRoles(ctx.Roles, ResolveUserRoles(ctx.Username, ps.Roles))

	// Evaluate policies top-to-bottom, first match wins
	var maskingRules []MaskingRule

	for _, rule := range ps.Policies {
		if !e.matchRule(ctx, &rule) {
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

func (e *Engine) matchRule(ctx *Context, rule *PolicyRule) bool {
	// Match roles
	if !matchRole(ctx, rule.Match.Roles) {
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

	// Include custom condition plugin names so cached decisions are invalidated
	// when plugin membership or configurations change.
	ps := e.loader.Current()
	if ps != nil {
		for _, p := range ps.Policies {
			if p.Condition != nil && len(p.Condition.Custom) > 0 {
				combined += "|custom:"
				for name := range p.Condition.Custom {
					combined += name + ","
				}
			}
		}
	}

	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:16])
}

// decisionCache is a bounded TTL cache for policy decisions with LRU eviction.
// When full, the least recently used entry is evicted to make room for the new one.
// Entries older than TTL are purged at the next set operation.
type decisionCache struct {
	mu          sync.Mutex
	entries     map[string]*list.Element // key → list element
	order       *list.List               // LRU order: Front = most recently used
	maxSize     int
	ttl         time.Duration
	lastCleanup time.Time
}

type cacheEntry struct {
	key      string
	decision *Decision
	expiry   time.Time
}

func newDecisionCache(maxSize int, ttl time.Duration) *decisionCache {
	return &decisionCache{
		entries:     make(map[string]*list.Element, maxSize),
		order:       list.New(),
		maxSize:     maxSize,
		ttl:         ttl,
		lastCleanup: time.Now(),
	}
}

func (c *decisionCache) get(key string) (*Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	entry := elem.Value.(*cacheEntry)
	if time.Now().After(entry.expiry) {
		c.removeElement(elem)
		return nil, false
	}

	// Move to front (most recently used)
	c.order.MoveToFront(elem)
	return entry.decision, true
}

func (c *decisionCache) set(key string, d *Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Periodic cleanup of expired entries (every TTL interval)
	if time.Since(c.lastCleanup) > c.ttl {
		c.purgeExpired()
		c.lastCleanup = time.Now()
	}

	// If the key already exists, update it and move to front
	if elem, ok := c.entries[key]; ok {
		elem.Value.(*cacheEntry).decision = d
		elem.Value.(*cacheEntry).expiry = time.Now().Add(c.ttl)
		c.order.MoveToFront(elem)
		return
	}

	// Evict LRU if full
	if c.order.Len() >= c.maxSize {
		c.evictLRU()
	}

	elem := c.order.PushFront(&cacheEntry{
		key:      key,
		decision: d,
		expiry:   time.Now().Add(c.ttl),
	})
	c.entries[key] = elem
}

func (c *decisionCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*list.Element, c.maxSize)
	c.order = list.New()
}

// evictLRU removes the single least recently used entry from the cache.
func (c *decisionCache) evictLRU() {
	elem := c.order.Back()
	if elem == nil {
		return
	}
	c.removeElement(elem)
}

// purgeExpired removes all entries whose TTL has expired.
func (c *decisionCache) purgeExpired() {
	now := time.Now()
	for elem := c.order.Back(); elem != nil; {
		entry := elem.Value.(*cacheEntry)
		if now.After(entry.expiry) {
			prev := elem.Prev()
			c.removeElement(elem)
			elem = prev
		} else {
			elem = elem.Prev()
		}
	}
}

// removeElement removes a list element and its map entry.
// Must be called while c.mu is held.
func (c *decisionCache) removeElement(elem *list.Element) {
	entry := elem.Value.(*cacheEntry)
	delete(c.entries, entry.key)
	c.order.Remove(elem)
}
