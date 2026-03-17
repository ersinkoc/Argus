package masking

import (
	"strings"

	"github.com/ersinkoc/argus/internal/policy"
)

// ColumnInfo holds column metadata.
type ColumnInfo struct {
	Name  string
	Index int
}

// FieldValue represents a single field value in a row.
type FieldValue struct {
	Data   []byte
	IsNull bool
}

// Pipeline is the streaming masking pipeline.
type Pipeline struct {
	rules        []policy.MaskingRule
	columnMap    map[int]Transformer // column index → transformer
	maxRows      int64
	rowCount     int64
	truncated    bool
	maskedCols   []string
	piiDetector  *PIIDetector
	piiScanned   bool // whether PII column scan has been done
}

// NewPipeline creates a masking pipeline from policy rules and column metadata.
func NewPipeline(rules []policy.MaskingRule, columns []ColumnInfo, maxRows int64) *Pipeline {
	p := &Pipeline{
		rules:     rules,
		columnMap: make(map[int]Transformer),
		maxRows:   maxRows,
	}

	// Map masking rules to column indices
	for _, rule := range rules {
		for _, col := range columns {
			if matchColumn(rule.Column, col.Name) {
				t := GetTransformer(rule.Transformer)
				p.columnMap[col.Index] = t
				p.maskedCols = append(p.maskedCols, col.Name)
			}
		}
	}

	return p
}

// SetPIIDetector attaches a PII detector for auto-discovery of sensitive columns.
func (p *Pipeline) SetPIIDetector(d *PIIDetector) {
	p.piiDetector = d
}

// HasMasking returns true if any columns need masking.
func (p *Pipeline) HasMasking() bool {
	return len(p.columnMap) > 0 || p.piiDetector != nil
}

// ApplyPIIDetection scans column names for PII patterns and adds masking rules.
// Called once when RowDescription is received (columns become known).
func (p *Pipeline) ApplyPIIDetection(columns []ColumnInfo) {
	if p.piiDetector == nil || p.piiScanned {
		return
	}
	p.piiScanned = true

	matches := p.piiDetector.DetectByColumnName(columns)
	for _, m := range matches {
		// Don't add if already masked by explicit rules
		if _, exists := p.columnMap[m.ColumnIndex]; exists {
			continue
		}
		t := GetTransformer(m.Transformer)
		p.columnMap[m.ColumnIndex] = t
		p.maskedCols = append(p.maskedCols, m.ColumnName)
	}
}

// MaskedColumns returns the list of masked column names.
func (p *Pipeline) MaskedColumns() []string {
	return p.maskedCols
}

// ProcessRow applies masking transformations to a single row.
// Returns the masked row and whether the row should be included.
func (p *Pipeline) ProcessRow(fields []FieldValue) ([]FieldValue, bool) {
	p.rowCount++

	// Check row limit
	if p.maxRows > 0 && p.rowCount > p.maxRows {
		p.truncated = true
		return nil, false
	}

	// Apply column transformations
	for idx, transformer := range p.columnMap {
		if idx < len(fields) && !fields[idx].IsNull {
			fields[idx].Data = transformer.Transform(fields[idx].Data)
		}
	}

	return fields, true
}

// MaskingRules returns the masking rules.
func (p *Pipeline) MaskingRules() []policy.MaskingRule {
	return p.rules
}

// MaxRowsLimit returns the max rows limit.
func (p *Pipeline) MaxRowsLimit() int64 {
	return p.maxRows
}

// IsTruncated returns true if the result was truncated by row limit.
func (p *Pipeline) IsTruncated() bool {
	return p.truncated
}

// RowCount returns the number of rows processed.
func (p *Pipeline) RowCount() int64 {
	return p.rowCount
}

// matchColumn checks if a column name matches a masking rule pattern.
func matchColumn(pattern, columnName string) bool {
	if pattern == "*" {
		return true
	}
	return strings.EqualFold(pattern, columnName)
}
