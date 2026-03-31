package audit

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CompactionConfig configures automatic log cleanup.
type CompactionConfig struct {
	MaxAge     time.Duration // delete logs older than this
	MaxFiles   int           // keep at most N log files
	DryRun     bool          // if true, only report what would be deleted
}

// CompactionResult reports what was cleaned up.
type CompactionResult struct {
	ScannedFiles int      `json:"scanned_files"`
	DeletedFiles int      `json:"deleted_files"`
	DeletedNames []string `json:"deleted_names,omitempty"`
	FreedBytes   int64    `json:"freed_bytes"`
	Errors       []string `json:"errors,omitempty"`
}

// CompactLogs cleans up old audit log files in the given directory.
// Looks for files matching the pattern: *.jsonl, *.jsonl.*, (rotated files)
func CompactLogs(dir string, cfg CompactionConfig) (*CompactionResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading log directory: %w", err)
	}

	result := &CompactionResult{}

	type logFile struct {
		name    string
		path    string
		modTime time.Time
		size    int64
	}

	var logFiles []logFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.Contains(name, ".jsonl") {
			continue
		}

		fullPath := filepath.Join(dir, name)
		info, err := os.Stat(fullPath)
		if err != nil {
			continue // file may have been deleted since ReadDir
		}

		logFiles = append(logFiles, logFile{
			name:    name,
			path:    fullPath,
			modTime: info.ModTime(),
			size:    info.Size(),
		})
	}

	result.ScannedFiles = len(logFiles)

	if len(logFiles) == 0 {
		return result, nil
	}

	// Sort by modification time, newest first
	sort.Slice(logFiles, func(i, j int) bool {
		return logFiles[i].modTime.After(logFiles[j].modTime)
	})

	now := time.Now()
	toDelete := make(map[string]bool)

	// Mark files older than MaxAge
	if cfg.MaxAge > 0 {
		for _, lf := range logFiles {
			if now.Sub(lf.modTime) > cfg.MaxAge {
				toDelete[lf.path] = true
			}
		}
	}

	// Mark files beyond MaxFiles count (keep newest)
	if cfg.MaxFiles > 0 && len(logFiles) > cfg.MaxFiles {
		for _, lf := range logFiles[cfg.MaxFiles:] {
			toDelete[lf.path] = true
		}
	}

	// Delete marked files
	for _, lf := range logFiles {
		if !toDelete[lf.path] {
			continue
		}

		if cfg.DryRun {
			result.DeletedFiles++
			result.DeletedNames = append(result.DeletedNames, lf.name)
			result.FreedBytes += lf.size
			continue
		}

		if err := os.Remove(lf.path); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("removing %s: %v", lf.name, err))
			continue
		}

		result.DeletedFiles++
		result.DeletedNames = append(result.DeletedNames, lf.name)
		result.FreedBytes += lf.size
		log.Printf("[argus] compacted audit log: %s (%.1f KB)", lf.name, float64(lf.size)/1024)
	}

	return result, nil
}
