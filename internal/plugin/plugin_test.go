package plugin

import "testing"

// mockTransformer implements TransformerPlugin
type mockTransformer struct {
	name string
}

func (m *mockTransformer) Name() string                          { return m.name }
func (m *mockTransformer) Type() Type                            { return TypeTransformer }
func (m *mockTransformer) Init(config map[string]any) error      { return nil }
func (m *mockTransformer) Close() error                          { return nil }
func (m *mockTransformer) Transform(v []byte, col string) []byte { return []byte("masked:" + string(v)) }

// mockAuditWriter implements AuditWriterPlugin
type mockAuditWriter struct{ name string }

func (m *mockAuditWriter) Name() string                             { return m.name }
func (m *mockAuditWriter) Type() Type                               { return TypeAuditWriter }
func (m *mockAuditWriter) Init(config map[string]any) error         { return nil }
func (m *mockAuditWriter) Close() error                             { return nil }
func (m *mockAuditWriter) WriteEvent(event map[string]any) error    { return nil }

func TestRegistryBasic(t *testing.T) {
	r := NewRegistry()

	if r.Count() != 0 {
		t.Error("initial count should be 0")
	}

	// Register transformer
	err := r.Register(&mockTransformer{name: "custom_mask"})
	if err != nil {
		t.Fatal(err)
	}

	if r.Count() != 1 {
		t.Errorf("count = %d", r.Count())
	}

	// Get
	p := r.Get("custom_mask")
	if p == nil {
		t.Fatal("should find plugin")
	}
	if p.Name() != "custom_mask" {
		t.Errorf("name = %q", p.Name())
	}

	// Get nonexistent
	if r.Get("nope") != nil {
		t.Error("nonexistent should return nil")
	}
}

func TestRegistryDuplicate(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockTransformer{name: "dup"})
	err := r.Register(&mockTransformer{name: "dup"})
	if err == nil {
		t.Error("duplicate should fail")
	}
}

func TestRegistryGetTransformers(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockTransformer{name: "t1"})
	r.Register(&mockTransformer{name: "t2"})
	r.Register(&mockAuditWriter{name: "a1"})

	transformers := r.GetTransformers()
	if len(transformers) != 2 {
		t.Errorf("transformers = %d, want 2", len(transformers))
	}

	writers := r.GetAuditWriters()
	if len(writers) != 1 {
		t.Errorf("writers = %d, want 1", len(writers))
	}
}

func TestRegistryList(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockTransformer{name: "t1"})
	r.Register(&mockAuditWriter{name: "a1"})

	list := r.List()
	if len(list) != 2 {
		t.Errorf("list = %d", len(list))
	}
	if list["t1"] != TypeTransformer {
		t.Error("t1 should be transformer")
	}
	if list["a1"] != TypeAuditWriter {
		t.Error("a1 should be audit_writer")
	}
}

func TestRegistryCloseAll(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockTransformer{name: "t1"})
	r.Register(&mockAuditWriter{name: "a1"})

	r.CloseAll() // should not panic
	// After close, count still shows plugins (they're not removed)
}

func TestTransformerPlugin(t *testing.T) {
	tp := &mockTransformer{name: "test"}
	result := tp.Transform([]byte("hello"), "col1")
	if string(result) != "masked:hello" {
		t.Errorf("transform = %q", result)
	}
}
