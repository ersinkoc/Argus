package audit

import (
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// QueryRecord is a full query record for forensic analysis and replay.
type QueryRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	SessionID   string    `json:"session_id"`
	Username    string    `json:"username"`
	Database    string    `json:"database"`
	SQL         string    `json:"sql"`
	CommandType string    `json:"command_type"`
	Tables      []string  `json:"tables,omitempty"`
	Duration    int64     `json:"duration_us"` // microseconds
	RowCount    int64     `json:"row_count"`
	Action      string    `json:"action"`
	PolicyName  string    `json:"policy_name,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	Error       string    `json:"error,omitempty"`
}

// QueryRecorder writes full query records for forensics and replay.
// Unlike audit logs (which may sanitize SQL), query records preserve
// the original SQL for authorized forensic use.
type QueryRecorder struct {
	mu      sync.Mutex
	file    *os.File
	encoder *json.Encoder
	enabled atomic.Bool
}

// NewQueryRecorder creates a recorder writing to the specified file.
func NewQueryRecorder(path string) (*QueryRecorder, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}

	r := &QueryRecorder{
		file:    f,
		encoder: json.NewEncoder(f),
	}
	r.enabled.Store(true)
	return r, nil
}

// Record writes a query record.
func (r *QueryRecorder) Record(rec QueryRecord) {
	if !r.enabled.Load() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.encoder.Encode(rec)
}

// Close closes the recorder.
func (r *QueryRecorder) Close() error {
	r.enabled.Store(false)
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

// Enabled returns whether recording is active.
func (r *QueryRecorder) Enabled() bool {
	return r.enabled.Load()
}
