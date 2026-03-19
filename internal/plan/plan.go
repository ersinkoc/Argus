// Package plan provides PostgreSQL query plan cost analysis via EXPLAIN.
// It executes EXPLAIN (FORMAT JSON) on the backend connection and extracts
// the planner's total cost estimate, which is more accurate than heuristic
// scoring for policy enforcement via the plan_cost_gte condition.
package plan

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	// DefaultTimeout is the maximum time to wait for an EXPLAIN response.
	DefaultTimeout = 500 * time.Millisecond
)

// Result holds the parsed PostgreSQL query plan.
type Result struct {
	TotalCost float64 // planner's top-level total cost estimate
	PlanRows  float64 // estimated number of rows
	PlanWidth int     // estimated row width in bytes
}

// ExplainPG runs EXPLAIN (FORMAT JSON) <sql> on the given backend connection
// and returns the plan cost. It must be called before forwarding the real
// query — the connection is shared so care must be taken by the caller.
//
// Only works for PostgreSQL Simple Query protocol connections that are
// already past the startup/auth phase.
func ExplainPG(ctx context.Context, backend net.Conn, sql string, timeout time.Duration) (*Result, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	// Send EXPLAIN query as Simple Query
	explainSQL := "EXPLAIN (FORMAT JSON) " + sql
	msg := buildSimpleQuery(explainSQL)
	if err := backend.SetWriteDeadline(deadline); err != nil {
		return nil, fmt.Errorf("plan: set write deadline: %w", err)
	}
	if _, err := backend.Write(msg); err != nil {
		return nil, fmt.Errorf("plan: sending EXPLAIN: %w", err)
	}

	if err := backend.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("plan: set read deadline: %w", err)
	}
	defer backend.SetReadDeadline(time.Time{}) //nolint:errcheck // best-effort reset
	defer backend.SetWriteDeadline(time.Time{}) //nolint:errcheck

	return readExplainResult(backend)
}

// buildSimpleQuery encodes a PostgreSQL Simple Query ('Q') message.
func buildSimpleQuery(sql string) []byte {
	payload := []byte(sql)
	payload = append(payload, 0) // null terminator

	buf := make([]byte, 1+4+len(payload))
	buf[0] = 'Q'
	binary.BigEndian.PutUint32(buf[1:], uint32(4+len(payload)))
	copy(buf[5:], payload)
	return buf
}

// readMessage reads one PostgreSQL backend message (type byte + int32 len + payload).
func readMessage(r io.Reader) (byte, []byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	msgType := hdr[0]
	msgLen := int(binary.BigEndian.Uint32(hdr[1:])) - 4
	if msgLen < 0 {
		return 0, nil, fmt.Errorf("plan: negative message length")
	}
	payload := make([]byte, msgLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return msgType, payload, nil
}

// readExplainResult reads backend messages until ReadyForQuery, collecting DataRow text.
func readExplainResult(backend net.Conn) (*Result, error) {
	var jsonBuf strings.Builder

	for {
		msgType, payload, err := readMessage(backend)
		if err != nil {
			return nil, fmt.Errorf("plan: reading backend message: %w", err)
		}

		switch msgType {
		case 'T': // RowDescription — ignore
		case 'D': // DataRow
			text := extractDataRowText(payload)
			jsonBuf.WriteString(text)
		case 'C': // CommandComplete
		case 'Z': // ReadyForQuery — done
			return parseExplainJSON(jsonBuf.String())
		case 'E': // ErrorResponse
			msg := extractErrorMessage(payload)
			return nil, fmt.Errorf("plan: EXPLAIN error: %s", msg)
		// ignore: notice ('N'), parameter status ('S'), etc.
		}
	}
}

// extractDataRowText extracts text fields from a DataRow payload.
// Each field is: int32 length (-1 = NULL), then bytes.
func extractDataRowText(payload []byte) string {
	if len(payload) < 2 {
		return ""
	}
	fieldCount := int(binary.BigEndian.Uint16(payload[:2]))
	off := 2
	var sb strings.Builder
	for i := 0; i < fieldCount && off < len(payload); i++ {
		if off+4 > len(payload) {
			break
		}
		flen := int(int32(binary.BigEndian.Uint32(payload[off:])))
		off += 4
		if flen < 0 {
			continue // NULL
		}
		if off+flen > len(payload) {
			break
		}
		sb.Write(payload[off : off+flen])
		off += flen
	}
	return sb.String()
}

// extractErrorMessage extracts the 'M' (message) field from an ErrorResponse payload.
func extractErrorMessage(payload []byte) string {
	for i := 0; i < len(payload)-1; i++ {
		if payload[i] == 'M' {
			end := i + 1
			for end < len(payload) && payload[end] != 0 {
				end++
			}
			return string(payload[i+1 : end])
		}
	}
	return "unknown error"
}

// pgExplainOutput is the top-level structure returned by EXPLAIN (FORMAT JSON).
type pgExplainOutput []struct {
	Plan pgPlanNode `json:"Plan"`
}

type pgPlanNode struct {
	TotalCost  float64 `json:"Total Cost"`
	PlanRows   float64 `json:"Plan Rows"`
	PlanWidth  int     `json:"Plan Width"`
}

// parseExplainJSON parses the JSON output from EXPLAIN (FORMAT JSON).
func parseExplainJSON(raw string) (*Result, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("plan: empty EXPLAIN output")
	}

	var out pgExplainOutput
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("plan: parsing EXPLAIN JSON: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("plan: EXPLAIN returned no plans")
	}

	return &Result{
		TotalCost: out[0].Plan.TotalCost,
		PlanRows:  out[0].Plan.PlanRows,
		PlanWidth: out[0].Plan.PlanWidth,
	}, nil
}
