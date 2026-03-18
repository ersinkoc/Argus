package policy

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ersinkoc/argus/internal/inspection"
)

// matchRole checks if the context matches the role criteria.
func matchRole(ctx *Context, roles []string, policyRoles map[string]Role) bool {
	if len(roles) == 0 {
		return true
	}

	userRoles := resolveRoles(ctx.Username, policyRoles)

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

	// SQL contains
	if len(cond.SQLContains) > 0 {
		upper := strings.ToUpper(ctx.RawSQL)
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
		if !matchWorkHours(ctx.Timestamp, cond.WorkHours) {
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
		upper := strings.ToUpper(ctx.RawSQL)
		for _, s := range cond.SQLNotContains {
			if !strings.Contains(upper, strings.ToUpper(s)) {
				// SQL does not contain this string → condition matches
				return true
			}
		}
		// SQL contains all strings → condition does not match
		return false
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
		joinCount := countJoins(ctx.RawSQL)
		if joinCount < cond.MaxJoins {
			return false
		}
	}

	// SQL injection detection
	if cond.SQLInjection {
		if !detectSQLInjection(ctx.RawSQL) {
			return false
		}
	}

	return true
}

// countJoins counts JOIN keywords in SQL.
func countJoins(sql string) int {
	upper := strings.ToUpper(sql)
	// Count all JOIN occurrences (each INNER/LEFT/RIGHT/CROSS/FULL JOIN contains exactly one " JOIN ")
	return strings.Count(upper, " JOIN ")
}

// detectSQLInjection checks for common SQL injection patterns.
func detectSQLInjection(sql string) bool {
	upper := strings.ToUpper(sql)

	// Tautology patterns: OR 1=1, OR 'a'='a', OR true
	for _, pattern := range sqliTautologyPatterns {
		if strings.Contains(upper, pattern) {
			return true
		}
	}

	// UNION-based injection
	if strings.Contains(upper, "UNION") && strings.Contains(upper, "SELECT") {
		// UNION SELECT in a query that also has another SELECT
		unionIdx := strings.Index(upper, "UNION")
		selectAfter := strings.Contains(upper[unionIdx:], "SELECT")
		if selectAfter {
			return true
		}
	}

	// Comment-based termination: '; -- or '; #
	if (strings.Contains(sql, "'--") || strings.Contains(sql, "'#") ||
		strings.Contains(sql, "\"--") || strings.Contains(sql, "\"#")) {
		return true
	}

	// Stacked queries with dangerous commands after semicolon
	if idx := strings.Index(sql, ";"); idx >= 0 && idx < len(sql)-1 {
		after := strings.TrimSpace(strings.ToUpper(sql[idx+1:]))
		for _, cmd := range []string{"DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "EXEC", "CREATE", "GRANT", "SHUTDOWN"} {
			if strings.HasPrefix(after, cmd) {
				return true
			}
		}
	}

	// Hex/char encoding tricks — flag CHAR()/CHR()/CONCAT() with multiple args (obfuscation)
	if strings.Contains(upper, "CHAR(") || strings.Contains(upper, "CHR(") || strings.Contains(upper, "CONCAT(") {
		// Only flag if combined with suspicious context
		if strings.Contains(upper, "UNION") || strings.Contains(upper, "DROP") || strings.Contains(upper, "EXEC") {
			return true
		}
		// CHAR/CHR with comma-separated args (building strings char-by-char)
		for _, fn := range []string{"CHAR(", "CHR("} {
			if idx := strings.Index(upper, fn); idx >= 0 {
				rest := upper[idx+len(fn):]
				if strings.Contains(rest[:min(len(rest), 30)], ",") {
					return true
				}
			}
		}
	}

	// Sleep/benchmark-based blind injection
	if strings.Contains(upper, "SLEEP(") || strings.Contains(upper, "BENCHMARK(") ||
		strings.Contains(upper, "PG_SLEEP(") || strings.Contains(upper, "WAITFOR DELAY") {
		return true
	}

	// System command execution
	if strings.Contains(upper, "XP_CMDSHELL") || strings.Contains(upper, "INTO OUTFILE") ||
		strings.Contains(upper, "INTO DUMPFILE") || strings.Contains(upper, "LOAD_FILE(") {
		return true
	}

	return false
}

// sqliTautologyPatterns are common tautology injection patterns.
var sqliTautologyPatterns = []string{
	"OR 1=1", "OR '1'='1'", "OR 'A'='A'", "OR TRUE",
	"OR 1 =1", "OR 1= 1", "OR 1 = 1",
	"OR ''='", "OR \"\"=\"",
	"' OR '1", "' OR '", "\" OR \"",
}

func matchWorkHours(t time.Time, hoursRange string) bool {
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
