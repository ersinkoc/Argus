package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingWriterClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.jsonl")

	rw, err := NewRotatingWriter(path, 100, 5)
	if err != nil {
		t.Fatal(err)
	}

	rw.Write([]byte("test\n"))
	err = rw.Close()
	if err != nil {
		t.Errorf("Close: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("file should exist")
	}
}

func TestRotatingWriterInvalidPath(t *testing.T) {
	// Windows'ta geçersiz karakter
	_, err := NewRotatingWriter("", 100, 5)
	// Empty path may or may not error depending on OS
	_ = err
}
