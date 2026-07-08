package audit

import (
	"encoding/json"
	"fmt"
	"os"
)

// VerifyChain reads a JSONL audit log file and verifies the event hash chain.
func VerifyChain(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	scanner := newLineScanner(f)
	line := 0
	prevHash := ""
	for scanner.Scan() {
		line++
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("line %d: decode audit event: %w", line, err)
		}
		if event.PrevHash != prevHash {
			return fmt.Errorf("line %d: prev_hash mismatch", line)
		}
		if want := eventHash(event); event.Hash != want {
			return fmt.Errorf("line %d: hash mismatch", line)
		}
		prevHash = event.Hash
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading audit log: %w", err)
	}
	return nil
}
