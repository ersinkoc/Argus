package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCompactLogsByAge(t *testing.T) {
	dir := t.TempDir()

	// Create files with different ages
	newFile := filepath.Join(dir, "audit.jsonl")
	os.WriteFile(newFile, []byte("new\n"), 0644)

	oldFile := filepath.Join(dir, "audit.jsonl.2024-01-01")
	os.WriteFile(oldFile, []byte("old\n"), 0644)
	// Set old modification time
	oldTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(oldFile, oldTime, oldTime)

	result, err := CompactLogs(dir, CompactionConfig{
		MaxAge: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("CompactLogs: %v", err)
	}

	if result.ScannedFiles != 2 {
		t.Errorf("scanned = %d, want 2", result.ScannedFiles)
	}
	if result.DeletedFiles != 1 {
		t.Errorf("deleted = %d, want 1", result.DeletedFiles)
	}

	// New file should still exist
	if _, err := os.Stat(newFile); os.IsNotExist(err) {
		t.Error("new file should still exist")
	}
	// Old file should be deleted
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Error("old file should be deleted")
	}
}

func TestCompactLogsByCount(t *testing.T) {
	dir := t.TempDir()

	// Create 5 files
	for i := 0; i < 5; i++ {
		name := filepath.Join(dir, "audit.jsonl."+string(rune('a'+i)))
		os.WriteFile(name, []byte("data\n"), 0644)
		// Stagger mod times
		ts := time.Now().Add(-time.Duration(i) * time.Hour)
		os.Chtimes(name, ts, ts)
	}

	result, err := CompactLogs(dir, CompactionConfig{
		MaxFiles: 2,
	})
	if err != nil {
		t.Fatalf("CompactLogs: %v", err)
	}

	if result.DeletedFiles != 3 {
		t.Errorf("deleted = %d, want 3 (keep 2 newest)", result.DeletedFiles)
	}
}

func TestCompactLogsDryRun(t *testing.T) {
	dir := t.TempDir()

	f := filepath.Join(dir, "audit.jsonl.old")
	os.WriteFile(f, []byte("data\n"), 0644)
	oldTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(f, oldTime, oldTime)

	result, err := CompactLogs(dir, CompactionConfig{
		MaxAge: 24 * time.Hour,
		DryRun: true,
	})
	if err != nil {
		t.Fatalf("CompactLogs: %v", err)
	}

	if result.DeletedFiles != 1 {
		t.Errorf("dry-run should report 1 deletion, got %d", result.DeletedFiles)
	}

	// File should still exist (dry run)
	if _, err := os.Stat(f); os.IsNotExist(err) {
		t.Error("dry-run should not actually delete files")
	}
}

func TestCompactLogsEmptyDir(t *testing.T) {
	dir := t.TempDir()

	result, err := CompactLogs(dir, CompactionConfig{MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("CompactLogs: %v", err)
	}
	if result.ScannedFiles != 0 {
		t.Errorf("scanned = %d, want 0", result.ScannedFiles)
	}
}
