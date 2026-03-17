package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// 1MB max size — we'll write enough to trigger rotation
	rw, err := NewRotatingWriter(path, 1, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}

	// Write 1MB+ to trigger rotation
	line := make([]byte, 100*1024) // 100KB
	for i := range line {
		line[i] = 'A'
	}
	line = append(line, '\n')

	for range 12 {
		rw.Write(line) // 12 * 100KB = 1.2MB → triggers rotation
	}

	rw.Close()

	// Check that rotated files exist
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) < 2 {
		t.Errorf("expected at least 2 files after rotation, got %d", len(entries))
		for _, e := range entries {
			t.Logf("  %s", e.Name())
		}
	}
}

func TestRotatingWriterCreateDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "audit.jsonl")

	rw, err := NewRotatingWriter(path, 100, 10)
	if err != nil {
		t.Fatalf("NewRotatingWriter should create parent dir: %v", err)
	}
	rw.Write([]byte("test\n"))
	rw.Close()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("file should exist")
	}
}
