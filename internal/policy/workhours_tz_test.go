package policy

import (
	"testing"
	"time"
)

// TestMatchWorkHoursTimezone proves the window is interpreted in the given IANA timezone.
func TestMatchWorkHoursTimezone(t *testing.T) {
	// 12:00 UTC.
	ts := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	// In UTC, 12:00 is INSIDE 09:00-17:00 → matchWorkHours reports "outside" == false.
	if matchWorkHours(ts, "09:00-17:00", "UTC") {
		t.Fatal("12:00 UTC should be inside the UTC window")
	}
	// In America/New_York (UTC-5), 12:00 UTC == 07:00 local → OUTSIDE the window == true.
	if !matchWorkHours(ts, "09:00-17:00", "America/New_York") {
		t.Fatal("12:00 UTC == 07:00 New York should be outside the window")
	}
	// Unknown tz falls back to the timestamp's own location (UTC here) → inside.
	if matchWorkHours(ts, "09:00-17:00", "Not/AZone") {
		t.Fatal("unknown tz should fall back to the timestamp location (inside)")
	}
}
