package audit

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// ExportCSV exports audit events from a JSON lines file to CSV format.
func ExportCSV(logPath string, w io.Writer, filter SearchFilter) (int, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return 0, fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()

	// Write header
	header := []string{
		"timestamp", "event_type", "session_id", "username",
		"client_ip", "database", "command_type", "action",
		"risk_level", "policy_name", "row_count", "duration_ms",
		"reason", "error",
	}
	// csv.Writer buffers internally (4096 bytes), so Write errors only surface on Flush.
	csvWriter.Write(header)

	count := 0
	scanner := newLineScanner(f)

	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}

		if !matchesFilter(&event, &filter) {
			continue
		}

		record := []string{
			event.Timestamp.Format(time.RFC3339),
			event.EventType,
			event.SessionID,
			event.Username,
			event.ClientIP,
			event.Database,
			event.CommandType,
			event.Action,
			event.RiskLevel,
			event.PolicyName,
			fmt.Sprintf("%d", event.RowCount),
			fmt.Sprintf("%d", event.Duration.Milliseconds()),
			event.Reason,
			event.Error,
		}

		if err := csvWriter.Write(record); err != nil {
			return count, err
		}
		count++

		if filter.Limit > 0 && count >= filter.Limit {
			break
		}
	}

	return count, scanner.Err()
}

func newLineScanner(f *os.File) *lineScanner {
	return &lineScanner{
		scanner: json.NewDecoder(f),
		f:       f,
	}
}

// lineScanner wraps os.File for line-by-line JSON reading.
type lineScanner struct {
	scanner *json.Decoder
	f       *os.File
	buf     []byte
	err     error
}

func (s *lineScanner) Scan() bool {
	s.buf = nil
	// Read raw JSON token
	var raw json.RawMessage
	if err := s.scanner.Decode(&raw); err != nil {
		if err != io.EOF {
			s.err = err
		}
		return false
	}
	s.buf = raw
	return true
}

func (s *lineScanner) Bytes() []byte {
	return s.buf
}

func (s *lineScanner) Err() error {
	return s.err
}
