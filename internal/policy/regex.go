package policy

import (
	"regexp"
	"sync"
)

// RegexCache caches compiled regular expressions for policy condition matching.
type RegexCache struct {
	mu    sync.RWMutex
	cache map[string]*regexp.Regexp
}

var globalRegexCache = &RegexCache{
	cache: make(map[string]*regexp.Regexp),
}

// GetRegex returns a compiled regex, using cache for repeated patterns.
func GetRegex(pattern string) (*regexp.Regexp, error) {
	globalRegexCache.mu.RLock()
	if re, ok := globalRegexCache.cache[pattern]; ok {
		globalRegexCache.mu.RUnlock()
		return re, nil
	}
	globalRegexCache.mu.RUnlock()

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	globalRegexCache.mu.Lock()
	globalRegexCache.cache[pattern] = re
	globalRegexCache.mu.Unlock()

	return re, nil
}

// MatchSQLRegex checks if SQL matches a regex pattern.
func MatchSQLRegex(sql string, patterns []string) bool {
	for _, pattern := range patterns {
		re, err := GetRegex(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(sql) {
			return true
		}
	}
	return false
}
