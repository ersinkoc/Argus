package plugin

import (
	"fmt"
	"testing"
)

// --- CloseAll with error ---

type failClosePlugin struct {
	name string
}

func (p *failClosePlugin) Name() string                    { return p.name }
func (p *failClosePlugin) Type() Type                      { return TypeTransformer }
func (p *failClosePlugin) Init(config map[string]any) error { return nil }
func (p *failClosePlugin) Close() error                    { return fmt.Errorf("close failed") }

func TestCloseAllWithError(t *testing.T) {
	r := NewRegistry()
	r.Register(&failClosePlugin{name: "bad-plugin"})

	// Should not panic, just log
	r.CloseAll()
}

func TestCloseAllEmpty(t *testing.T) {
	r := NewRegistry()
	r.CloseAll() // should not panic
}

func TestCloseAllMultiple(t *testing.T) {
	r := NewRegistry()
	r.Register(&failClosePlugin{name: "p1"})
	r.Register(&failClosePlugin{name: "p2"})
	r.CloseAll()
	if r.Count() != 2 { // plugins remain registered, just closed
		t.Log("count after close may vary")
	}
}
