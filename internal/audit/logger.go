package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Logger is the async audit logger.
type Logger struct {
	eventCh    chan Event
	writers    []io.Writer
	level      LogLevel
	sqlMaxLen  int
	wg         sync.WaitGroup
	closed     atomic.Bool
	dropped    atomic.Int64
	closeCh    chan struct{}
}

// NewLogger creates a new audit logger.
func NewLogger(bufferSize int, level LogLevel, sqlMaxLen int) *Logger {
	if bufferSize <= 0 {
		bufferSize = 10000
	}
	if sqlMaxLen <= 0 {
		sqlMaxLen = 4096
	}
	l := &Logger{
		eventCh:   make(chan Event, bufferSize),
		level:     level,
		sqlMaxLen: sqlMaxLen,
		closeCh:   make(chan struct{}),
	}
	return l
}

// AddWriter adds an output writer (file, stdout, etc.).
func (l *Logger) AddWriter(w io.Writer) {
	l.writers = append(l.writers, w)
}

// AddFileWriter opens a file for audit output.
func (l *Logger) AddFileWriter(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("opening audit file %q: %w", path, err)
	}
	l.writers = append(l.writers, f)
	return nil
}

// Start begins the async writer goroutine.
func (l *Logger) Start() {
	if len(l.writers) == 0 {
		l.writers = append(l.writers, os.Stdout)
	}
	l.wg.Add(1)
	go l.writeLoop()
}

// Log sends an event to the audit log.
// Events are filtered based on the logger's configured level:
//   - Minimal: connection lifecycle, blocked commands, admin events only
//   - Standard: all events (default)
//   - Verbose: all events
func (l *Logger) Log(event Event) {
	if l.closed.Load() {
		return
	}
	if l.level == LevelMinimal && !isMinimalEvent(event.EventType) {
		return
	}
	if event.ID == "" {
		event.ID = generateID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	// Truncate long SQL
	if len(event.Command) > l.sqlMaxLen {
		event.Command = event.Command[:l.sqlMaxLen] + "...[truncated]"
	}

	select {
	case l.eventCh <- event:
	default:
		l.dropped.Add(1)
	}
}

// isMinimalEvent returns true for events that should always be logged even at minimal level.
func isMinimalEvent(eventType string) bool {
	switch eventType {
	case "connection_open", "connection_close",
		"auth_success", "auth_failure",
		"command_blocked", "session_timeout",
		"session_killed", "policy_reloaded":
		return true
	}
	return false
}

// ShouldLog checks if an event should be logged at the current level.
func (l *Logger) ShouldLog(eventType EventType, level LogLevel) bool {
	return level <= l.level
}

// DroppedCount returns the number of dropped events.
func (l *Logger) DroppedCount() int64 {
	return l.dropped.Load()
}

// Close stops the logger and flushes remaining events.
func (l *Logger) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	close(l.closeCh)
	l.wg.Wait()

	// Close any file writers
	for _, w := range l.writers {
		if c, ok := w.(io.Closer); ok && c != os.Stdout && c != os.Stderr {
			c.Close()
		}
	}
	return nil
}

func (l *Logger) writeLoop() {
	defer l.wg.Done()
	encoder := json.NewEncoder(io.MultiWriter(l.writers...))

	for {
		select {
		case event := <-l.eventCh:
			if err := encoder.Encode(event); err != nil {
				log.Printf("[argus] audit write error: %v", err)
			}
		case <-l.closeCh:
			// Drain remaining events
			for {
				select {
				case event := <-l.eventCh:
					if err := encoder.Encode(event); err != nil {
						log.Printf("[argus] audit write error: %v", err)
					}
				default:
					return
				}
			}
		}
	}
}

func generateID() string {
	// Simple ULID-like: timestamp + random
	b := make([]byte, 10)
	rand.Read(b)
	ts := time.Now().UnixMilli()
	return fmt.Sprintf("%013x%s", ts, hex.EncodeToString(b[:6]))
}
