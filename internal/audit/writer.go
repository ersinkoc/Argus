package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RotatingWriter is a file writer that rotates based on size.
type RotatingWriter struct {
	path      string
	maxSizeMB int
	maxFiles  int
	mu        sync.Mutex
	file      *os.File
	written   int64
}

// NewRotatingWriter creates a new rotating file writer.
func NewRotatingWriter(path string, maxSizeMB, maxFiles int) (*RotatingWriter, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = 100
	}
	if maxFiles <= 0 {
		maxFiles = 10
	}

	w := &RotatingWriter{
		path:      path,
		maxSizeMB: maxSizeMB,
		maxFiles:  maxFiles,
	}

	if err := w.openFile(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *RotatingWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check if rotation is needed
	if w.written+int64(len(p)) > int64(w.maxSizeMB)*1024*1024 {
		if err := w.rotate(); err != nil {
			return 0, fmt.Errorf("rotating audit log: %w", err)
		}
	}

	n, err = w.file.Write(p)
	w.written += int64(n)
	return n, err
}

// Close closes the underlying file.
func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

func (w *RotatingWriter) openFile() error {
	dir := filepath.Dir(w.path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating audit log directory: %w", err)
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}

	// Get current file size
	info, err := f.Stat()
	if err == nil {
		w.written = info.Size()
	}

	w.file = f
	return nil
}

func (w *RotatingWriter) rotate() error {
	// Close current file
	if w.file != nil {
		w.file.Close()
	}

	// Shift existing rotated files
	for i := w.maxFiles - 1; i > 0; i-- {
		oldPath := fmt.Sprintf("%s.%d", w.path, i)
		newPath := fmt.Sprintf("%s.%d", w.path, i+1)
		os.Rename(oldPath, newPath) // ignore error if doesn't exist
	}

	// Delete the oldest if it exceeds maxFiles
	oldest := fmt.Sprintf("%s.%d", w.path, w.maxFiles)
	os.Remove(oldest)

	// Rename current to .1
	timestamp := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", w.path, timestamp)
	if err := os.Rename(w.path, rotatedPath); err != nil {
		// Fallback: rename to .1
		os.Rename(w.path, fmt.Sprintf("%s.1", w.path))
	}

	// Open new file
	w.written = 0
	return w.openFile()
}
