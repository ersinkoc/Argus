package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func init() {
	// Register built-in example condition plugins.
	// Users can remove these or add their own via GlobalCondRegistry.Register().
	GlobalCondRegistry.Register(&timeWindowPlugin{})
	GlobalCondRegistry.Register(&sqlNotRegexPlugin{})
}

// ──────────────────────────────────────────────
// timeWindowPlugin — allow queries only within configured time windows.
// Policy JSON:
//
//	"condition": {
//	  "custom": {
//	    "time_window": {
//	      "windows": ["09:00-12:00", "14:00-18:00"],
//	      "timezone": "Europe/Istanbul"
//	    }
//	  }
//	}
// ──────────────────────────────────────────────

type timeWindowConfig struct {
	Windows  []string `json:"windows"`
	Timezone string   `json:"timezone"`
}

type timeWindowPlugin struct{}

func (p *timeWindowPlugin) Name() string { return "time_window" }

func (p *timeWindowPlugin) Eval(ctx *Context, raw json.RawMessage) (bool, error) {
	var cfg timeWindowConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return false, fmt.Errorf("time_window: invalid config: %w", err)
	}
	if len(cfg.Windows) == 0 {
		return false, fmt.Errorf("time_window: no windows configured")
	}

	loc := time.Local
	if cfg.Timezone != "" {
		var err error
		loc, err = time.LoadLocation(cfg.Timezone)
		if err != nil {
			return false, fmt.Errorf("time_window: invalid timezone %q: %w", cfg.Timezone, err)
		}
	}

	now := ctx.Timestamp.In(loc)
	currentMinutes := now.Hour()*60 + now.Minute()

	// Condition matches (rule applies) when current time is OUTSIDE all windows.
	for _, w := range cfg.Windows {
		start, end, err := parseTimeWindow(w)
		if err != nil {
			return false, fmt.Errorf("time_window: %w", err)
		}
		if currentMinutes >= start && currentMinutes <= end {
			return false, nil // inside a window → do NOT trigger the rule
		}
	}
	return true, nil // outside all windows → trigger the rule
}

func parseTimeWindow(s string) (start, end int, err error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid window %q (expected HH:MM-HH:MM)", s)
	}
	start = parseHM(strings.TrimSpace(parts[0]))
	end = parseHM(strings.TrimSpace(parts[1]))
	if start < 0 || end < 0 || start >= 24*60 || end >= 24*60 {
		return 0, 0, fmt.Errorf("invalid window %q", s)
	}
	return start, end, nil
}

func parseHM(s string) int {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return -1
	}
	h := 0
	for _, c := range parts[0] {
		if c < '0' || c > '9' {
			return -1
		}
		h = h*10 + int(c-'0')
	}
	m := 0
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return -1
		}
		m = m*10 + int(c-'0')
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return -1
	}
	return h*60 + m
}

// ──────────────────────────────────────────────
// sqlNotRegexPlugin — block queries whose SQL matches a regex pattern.
// Inverse of the built-in sql_regex (which triggers when the pattern matches).
// Policy JSON:
//
//	"condition": {
//	  "custom": {
//	    "sql_not_regex": {
//	      "patterns": ["(?i)SELECT\\s+\\*", "(?i)pg_catalog"]
//	    }
//	  }
//	}
// ──────────────────────────────────────────────

type sqlNotRegexConfig struct {
	Patterns []string `json:"patterns"`
}

type sqlNotRegexPlugin struct{}

func (p *sqlNotRegexPlugin) Name() string { return "sql_not_regex" }

func (p *sqlNotRegexPlugin) Eval(ctx *Context, raw json.RawMessage) (bool, error) {
	var cfg sqlNotRegexConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return false, fmt.Errorf("sql_not_regex: invalid config: %w", err)
	}
	if len(cfg.Patterns) == 0 {
		return false, nil
	}
	matches := MatchSQLRegex(ctx.RawSQL, cfg.Patterns)
	// Condition matches when NONE of the patterns match
	return !matches, nil
}
