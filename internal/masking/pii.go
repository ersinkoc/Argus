package masking

import (
	"regexp"
	"strings"
)

// PIIDetector scans column names and values for personally identifiable information.
type PIIDetector struct {
	columnPatterns map[string]*columnPattern
	valuePatterns  []*valuePattern
}

type columnPattern struct {
	regex       *regexp.Regexp
	transformer string
	category    string
}

type valuePattern struct {
	regex       *regexp.Regexp
	transformer string
	category    string
	validate    func(string) bool // optional extra validation (e.g., Luhn check)
}

// PIIMatch represents a detected PII field.
type PIIMatch struct {
	ColumnName  string
	ColumnIndex int
	Category    string // "email", "phone", "credit_card", "tc_kimlik", "iban", etc.
	Transformer string
	Source      string // "column_name" or "value_scan"
}

// NewPIIDetector creates a detector with built-in patterns for common PII.
func NewPIIDetector() *PIIDetector {
	d := &PIIDetector{
		columnPatterns: make(map[string]*columnPattern),
	}

	// Column name patterns → transformer mapping
	colPatterns := []struct {
		pattern     string
		transformer string
		category    string
	}{
		{`(?i)e[-_]?mail`, "partial_email", "email"},
		{`(?i)phone|mobile|tel|gsm|cep`, "partial_phone", "phone"},
		{`(?i)card[-_]?(number|no|num)|credit[-_]?card|pan`, "partial_card", "credit_card"},
		{`(?i)tc[-_]?(kimlik|no|num)|identity[-_]?(no|num)|ssn|social[-_]?sec`, "partial_tc", "national_id"},
		{`(?i)iban`, "partial_iban", "iban"},
		{`(?i)salary|wage|income|compensation|pay[-_]?(rate|amount)`, "redact", "financial"},
		{`(?i)pass(word)?|secret|token|api[-_]?key|access[-_]?key`, "redact", "credential"},
		{`(?i)birth[-_]?(date|day)|dob|date[-_]?of[-_]?birth`, "redact", "date_of_birth"},
		{`(?i)address|street|city|zip|postal`, "redact", "address"},
		{`(?i)tax[-_]?(id|no|num)|vat[-_]?(id|no|num)`, "redact", "tax_id"},
	}
	for _, cp := range colPatterns {
		re := regexp.MustCompile(cp.pattern)
		d.columnPatterns[cp.category] = &columnPattern{
			regex:       re,
			transformer: cp.transformer,
			category:    cp.category,
		}
	}

	// Value-level patterns (scan actual data)
	d.valuePatterns = []*valuePattern{
		{
			regex:       regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`),
			transformer: "partial_email",
			category:    "email",
		},
		{
			regex:       regexp.MustCompile(`^\+?[0-9]{10,15}$`),
			transformer: "partial_phone",
			category:    "phone",
		},
		{
			regex:       regexp.MustCompile(`^[0-9]{13,19}$`),
			transformer: "partial_card",
			category:    "credit_card",
			validate:    luhnCheck,
		},
		{
			regex:       regexp.MustCompile(`^[0-9]{11}$`),
			transformer: "partial_tc",
			category:    "national_id",
			validate:    tcKimlikCheck,
		},
		{
			regex:       regexp.MustCompile(`^[A-Z]{2}[0-9]{2}[A-Z0-9]{4,30}$`),
			transformer: "partial_iban",
			category:    "iban",
		},
	}

	return d
}

// DetectByColumnName scans column names for PII patterns.
func (d *PIIDetector) DetectByColumnName(columns []ColumnInfo) []PIIMatch {
	var matches []PIIMatch
	for _, col := range columns {
		for _, cp := range d.columnPatterns {
			if cp.regex.MatchString(col.Name) {
				matches = append(matches, PIIMatch{
					ColumnName:  col.Name,
					ColumnIndex: col.Index,
					Category:    cp.category,
					Transformer: cp.transformer,
					Source:      "column_name",
				})
				break // one match per column
			}
		}
	}
	return matches
}

// DetectByValue scans a row's values for PII patterns.
// This is more expensive — use only when enabled by policy.
func (d *PIIDetector) DetectByValue(columns []ColumnInfo, row []FieldValue) []PIIMatch {
	var matches []PIIMatch
	for i, field := range row {
		if field.IsNull || len(field.Data) == 0 {
			continue
		}
		val := strings.TrimSpace(string(field.Data))
		if len(val) < 5 || len(val) > 50 {
			continue // skip very short or very long values
		}

		for _, vp := range d.valuePatterns {
			if vp.regex.MatchString(val) {
				if vp.validate != nil && !vp.validate(val) {
					continue
				}
				colName := ""
				if i < len(columns) {
					colName = columns[i].Name
				}
				matches = append(matches, PIIMatch{
					ColumnName:  colName,
					ColumnIndex: i,
					Category:    vp.category,
					Transformer: vp.transformer,
					Source:      "value_scan",
				})
				break
			}
		}
	}
	return matches
}

// luhnCheck validates a number string using the Luhn algorithm (credit cards).
func luhnCheck(s string) bool {
	n := len(s)
	sum := 0
	alt := false
	for i := n - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// tcKimlikCheck validates a Turkish TC Kimlik number.
func tcKimlikCheck(s string) bool {
	if len(s) != 11 || s[0] == '0' {
		return false
	}
	digits := make([]int, 11)
	for i, c := range s {
		digits[i] = int(c - '0')
	}
	// Rule 1: sum of odd positions (1,3,5,7,9) * 7 - sum of even positions (2,4,6,8) mod 10 = digit 10
	oddSum := digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
	evenSum := digits[1] + digits[3] + digits[5] + digits[7]
	check10 := (oddSum*7 - evenSum) % 10
	if check10 < 0 {
		check10 += 10
	}
	if check10 != digits[9] {
		return false
	}
	// Rule 2: sum of first 10 digits mod 10 = digit 11
	sum := 0
	for i := 0; i < 10; i++ {
		sum += digits[i]
	}
	return sum%10 == digits[10]
}
