package policy

import (
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

// matchRole checks if the context matches the role criteria.
func matchRole(ctx *Context, roles []string) bool {
	if len(roles) == 0 {
		return true
	}

	// ctx.Roles is the authoritative, already-resolved role set (policy-file roles for the username
	// unioned with any identity-resolver roles — see Engine.evaluate). Match against it directly so
	// proxy-auth sessions, whose wire username is an opaque handle, are matched on their resolver roles.
	userRoles := ctx.Roles

	for _, rolePattern := range roles {
		negated := strings.HasPrefix(rolePattern, "!")
		roleName := strings.TrimPrefix(rolePattern, "!")

		hasRole := false
		for _, ur := range userRoles {
			if ur == roleName {
				hasRole = true
				break
			}
		}

		if negated {
			if hasRole {
				return false // user has the negated role, no match
			}
		} else {
			if !hasRole {
				return false // user doesn't have required role
			}
		}
	}

	return true
}

// resolveRoles determines which roles a username belongs to.
func resolveRoles(username string, roles map[string]Role) []string {
	var result []string
	for roleName, role := range roles {
		for _, pattern := range role.Users {
			if matchWildcard(pattern, username) {
				result = append(result, roleName)
				break
			}
		}
	}
	return result
}

// ResolveUserRoles is exported for use by the engine.
func ResolveUserRoles(username string, roles map[string]Role) []string {
	return resolveRoles(username, roles)
}

// unionRoles merges two role slices, preserving order (a before b) and dropping empties/duplicates.
func unionRoles(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	seen := make(map[string]struct{}, len(a)+len(b))
	add := func(roles []string) {
		for _, r := range roles {
			if r == "" {
				continue
			}
			if _, ok := seen[r]; ok {
				continue
			}
			seen[r] = struct{}{}
			out = append(out, r)
		}
	}
	add(a)
	add(b)
	return out
}

// matchCommands checks if the command type matches.
func matchCommands(cmdType inspection.CommandType, commands []string) bool {
	if len(commands) == 0 {
		return true
	}
	cmdStr := cmdType.String()
	for _, c := range commands {
		if strings.EqualFold(c, cmdStr) {
			return true
		}
	}
	return false
}

// matchDatabases checks if the database matches.
func matchDatabases(database string, databases []string) bool {
	if len(databases) == 0 {
		return true
	}
	for _, pattern := range databases {
		if matchWildcard(pattern, database) {
			return true
		}
	}
	return false
}

// matchTables checks if any of the query tables match the policy tables.
func matchTables(queryTables []string, policyTables []string) bool {
	if len(policyTables) == 0 {
		return true
	}
	for _, pt := range policyTables {
		for _, qt := range queryTables {
			if matchWildcard(pt, qt) {
				return true
			}
		}
	}
	return false
}

// matchCondition checks additional conditions.
func matchCondition(ctx *Context, cond *ConditionConfig) bool {
	if cond == nil {
		return true
	}

	// Pre-compute uppercased SQL once for all string-matching conditions
	var upper string
	if len(cond.SQLContains) > 0 || len(cond.SQLNotContains) > 0 || cond.SQLInjection || cond.MaxJoins > 0 {
		upper = strings.ToUpper(ctx.RawSQL)
	}

	// SQL contains
	if len(cond.SQLContains) > 0 {
		allFound := true
		for _, s := range cond.SQLContains {
			if !strings.Contains(upper, strings.ToUpper(s)) {
				allFound = false
				break
			}
		}
		if !allFound {
			return false
		}
	}

	// Risk level
	if cond.RiskLevelGTE != "" {
		threshold := inspection.ParseRiskLevel(cond.RiskLevelGTE)
		if ctx.RiskLevel < threshold {
			return false
		}
	}

	// Work hours
	if cond.WorkHours != "" {
		if !matchWorkHours(ctx.Timestamp, cond.WorkHours, cond.WorkHoursTz) {
			// Condition is "must be within work hours to trigger"
			// If currently in work hours, condition matches (e.g., for blocking outside hours, negate logic)
			// Actually: if the condition says work_hours: "08:00-19:00", it means
			// the rule applies when the user is OUTSIDE these hours (for blocking)
			// Let's interpret: if current time is within work hours, this condition does NOT match
			// (the rule is meant to block outside work hours)
			return false
		}
	}

	// Work days
	if len(cond.WorkDays) > 0 {
		if !matchWorkDays(ctx.Timestamp, cond.WorkDays) {
			return false
		}
	}

	// Source IP restrictions
	if len(cond.SourceIPIn) > 0 {
		if !matchIPIn(ctx.ClientIP, cond.SourceIPIn) {
			return false
		}
	}
	if len(cond.SourceIPNotIn) > 0 {
		if matchIPIn(ctx.ClientIP, cond.SourceIPNotIn) {
			return false
		}
	}

	// Query cost threshold
	if cond.MaxCostGTE > 0 {
		if ctx.CostScore < cond.MaxCostGTE {
			return false
		}
	}

	// SQL regex patterns
	if len(cond.SQLRegex) > 0 {
		if !MatchSQLRegex(ctx.RawSQL, cond.SQLRegex) {
			return false
		}
	}

	// SQL not contains — matches when the SQL does NOT contain ALL specified strings
	if len(cond.SQLNotContains) > 0 {
		allContained := true
		for _, s := range cond.SQLNotContains {
			if !strings.Contains(upper, strings.ToUpper(s)) {
				allContained = false
				break
			}
		}
		if allContained {
			// SQL contains all specified strings → condition does not match
			return false
		}
	}

	// Max query length
	if cond.MaxQueryLength > 0 {
		if len(ctx.RawSQL) < cond.MaxQueryLength {
			return false
		}
	}

	// Max tables
	if cond.MaxTables > 0 {
		if len(ctx.Tables) < cond.MaxTables {
			return false
		}
	}

	// Require WHERE on write operations
	if cond.RequireWhere {
		if ctx.HasWhere {
			return false // has WHERE → condition does not trigger
		}
	}

	// Max JOINs
	if cond.MaxJoins > 0 {
		joinCount := countJoinsUpper(upper)
		if joinCount < cond.MaxJoins {
			return false
		}
	}

	// SQL injection detection
	if cond.SQLInjection {
		if !detectSQLInjectionUpper(upper) {
			return false
		}
	}

	// Real planner cost (from EXPLAIN) threshold.
	// If plan cost is unavailable (0), the condition cannot be evaluated
	// and is treated as not matching — the policy rule is skipped.
	if cond.PlanCostGTE > 0 {
		if ctx.PlanCost <= 0 || ctx.PlanCost < cond.PlanCostGTE {
			return false
		}
	}

	// Custom plugin conditions — evaluated through the global ConditionRegistry.
	for name, config := range cond.Custom {
		plugin := GlobalCondRegistry.Get(name)
		if plugin == nil {
			slog.Warn("unknown custom condition plugin", "name", name)
			return false
		}
		match, err := plugin.Eval(ctx, config)
		if err != nil {
			slog.Warn("custom condition plugin error", "name", name, "error", err)
			return false
		}
		if !match {
			return false
		}
	}

	return true
}

func matchWorkHours(t time.Time, hoursRange string, tz string) bool {
	// Interpret the window in the configured timezone (IANA name). Unknown/unsupported tz → fall back to
	// the timestamp's own location so the check still runs (gateway local time).
	if tz != "" {
		if loc, err := time.LoadLocation(tz); err == nil {
			t = t.In(loc)
		}
	}
	parts := strings.Split(hoursRange, "-")
	if len(parts) != 2 {
		return true
	}
	startParts := strings.Split(strings.TrimSpace(parts[0]), ":")
	endParts := strings.Split(strings.TrimSpace(parts[1]), ":")
	if len(startParts) != 2 || len(endParts) != 2 {
		return true
	}

	startHour, _ := strconv.Atoi(startParts[0])
	startMin, _ := strconv.Atoi(startParts[1])
	endHour, _ := strconv.Atoi(endParts[0])
	endMin, _ := strconv.Atoi(endParts[1])

	currentMinutes := t.Hour()*60 + t.Minute()
	startMinutes := startHour*60 + startMin
	endMinutes := endHour*60 + endMin

	// For "office-hours-contractors" rule: condition means "rule applies when OUTSIDE these hours"
	// So we return true when OUTSIDE work hours (to trigger the block)
	return currentMinutes < startMinutes || currentMinutes > endMinutes
}

func matchWorkDays(t time.Time, days []string) bool {
	currentDay := strings.ToLower(t.Weekday().String())
	for _, d := range days {
		if strings.ToLower(d) == currentDay {
			// Current day IS a work day → rule should NOT trigger (for blocking outside work days)
			return false
		}
	}
	// Current day is NOT in the work days list → trigger
	return true
}

func matchIPIn(ip net.IP, cidrs []string) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as single IP
			if net.ParseIP(cidr) != nil && net.ParseIP(cidr).Equal(ip) {
				return true
			}
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// matchWildcard supports simple * wildcard matching.
func matchWildcard(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(value, pattern[1:])
	}
	if strings.Contains(pattern, "*") {
		// Simple middle wildcard: split on *
		parts := strings.SplitN(pattern, "*", 2)
		return strings.HasPrefix(value, parts[0]) && strings.HasSuffix(value, parts[1])
	}
	return strings.EqualFold(pattern, value)
}
