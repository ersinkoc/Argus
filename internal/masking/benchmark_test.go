package masking

import (
	"testing"

	"github.com/ersinkoc/argus/internal/policy"
)

func BenchmarkPipelineNoMasking(b *testing.B) {
	pipeline := NewPipeline(nil, nil, 0)
	row := []FieldValue{
		{Data: []byte("1")},
		{Data: []byte("John Doe")},
		{Data: []byte("john@example.com")},
		{Data: []byte("50000")},
	}
	b.ResetTimer()
	for b.Loop() {
		pipeline.ProcessRow(row)
	}
}

func BenchmarkPipelineWithMasking(b *testing.B) {
	rules := []policy.MaskingRule{
		{Column: "email", Transformer: "partial_email"},
		{Column: "salary", Transformer: "redact"},
	}
	columns := []ColumnInfo{
		{Name: "id", Index: 0},
		{Name: "name", Index: 1},
		{Name: "email", Index: 2},
		{Name: "salary", Index: 3},
	}
	pipeline := NewPipeline(rules, columns, 0)

	b.ResetTimer()
	for b.Loop() {
		row := []FieldValue{
			{Data: []byte("1")},
			{Data: []byte("John Doe")},
			{Data: []byte("john@example.com")},
			{Data: []byte("50000")},
		}
		pipeline.ProcessRow(row)
	}
}

func BenchmarkTransformerPartialEmail(b *testing.B) {
	t := GetTransformer("partial_email")
	input := []byte("john.doe@example.com")
	b.ResetTimer()
	for b.Loop() {
		t.Transform(input)
	}
}

func BenchmarkTransformerRedact(b *testing.B) {
	t := GetTransformer("redact")
	input := []byte("sensitive data here")
	b.ResetTimer()
	for b.Loop() {
		t.Transform(input)
	}
}

func BenchmarkTransformerHash(b *testing.B) {
	t := GetTransformer("hash")
	input := []byte("john@example.com")
	b.ResetTimer()
	for b.Loop() {
		t.Transform(input)
	}
}

func BenchmarkTransformerPartialCard(b *testing.B) {
	t := GetTransformer("partial_card")
	input := []byte("4532123456785678")
	b.ResetTimer()
	for b.Loop() {
		t.Transform(input)
	}
}
