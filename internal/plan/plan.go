// Package plan provides query plan cost analysis via EXPLAIN for PostgreSQL
// and MySQL. It executes EXPLAIN on the backend connection and extracts the
// planner's total cost estimate, which is more accurate than heuristic
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

// ── MySQL ────────────────────────────────────────────────────────────────────

// ExplainMySQL runs EXPLAIN FORMAT=JSON <sql> on the given MySQL backend
// connection and returns the estimated query cost. It uses the raw MySQL
// wire protocol (COM_QUERY) to avoid importing the mysql package.
//
// Only works for MySQL connections that are already past the handshake phase
// (i.e. authentication is complete and the connection is ready for commands).
func ExplainMySQL(ctx context.Context, backend net.Conn, sql string, timeout time.Duration) (*Result, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	// Build COM_QUERY packet: header(3-byte LE len + seq=0) + 0x03 + sql bytes
	query := "EXPLAIN FORMAT=JSON " + sql
	payload := make([]byte, 1+len(query))
	payload[0] = 0x03 // COM_QUERY
	copy(payload[1:], query)

	pktLen := len(payload)
	buf := make([]byte, 4+pktLen)
	buf[0] = byte(pktLen)
	buf[1] = byte(pktLen >> 8)
	buf[2] = byte(pktLen >> 16)
	buf[3] = 0 // sequence ID

	copy(buf[4:], payload)

	if err := backend.SetWriteDeadline(deadline); err != nil {
		return nil, fmt.Errorf("plan: mysql set write deadline: %w", err)
	}
	if _, err := backend.Write(buf); err != nil {
		return nil, fmt.Errorf("plan: mysql sending EXPLAIN: %w", err)
	}

	if err := backend.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("plan: mysql set read deadline: %w", err)
	}
	defer backend.SetReadDeadline(time.Time{}) //nolint:errcheck
	defer backend.SetWriteDeadline(time.Time{}) //nolint:errcheck

	return readMySQLExplainResult(backend)
}

// readMySQLExplainResult reads a MySQL text result set and extracts the
// EXPLAIN FORMAT=JSON output. MySQL result set structure:
//   1. Column count packet (length-encoded int)
//   2. N column definition packets
//   3. EOF packet (0xfe)
//   4. Row data packets (length-encoded strings per column)
//   5. EOF packet (0xfe) or ERR packet (0xff)
func readMySQLExplainResult(r net.Conn) (*Result, error) {
	// Read column count packet
	pkt, err := readMySQLPacket(r)
	if err != nil {
		return nil, fmt.Errorf("plan: mysql reading column count: %w", err)
	}
	if len(pkt) == 0 {
		return nil, fmt.Errorf("plan: mysql empty column count packet")
	}
	// Check for ERR packet (first byte 0xff)
	if pkt[0] == 0xff {
		return nil, fmt.Errorf("plan: mysql EXPLAIN error: %s", mysqlErrorMessage(pkt))
	}
	colCount, _, err := readLenEnc(pkt, 0)
	if err != nil || colCount == 0 {
		return nil, fmt.Errorf("plan: mysql invalid column count")
	}

	// Skip column definition packets
	for i := uint64(0); i < colCount; i++ {
		if _, err := readMySQLPacket(r); err != nil {
			return nil, fmt.Errorf("plan: mysql reading column def: %w", err)
		}
	}

	// Read/skip EOF after column definitions (MySQL 4.1+)
	eof, err := readMySQLPacket(r)
	if err != nil {
		return nil, fmt.Errorf("plan: mysql reading EOF after columns: %w", err)
	}
	if len(eof) == 0 || eof[0] != 0xfe {
		return nil, fmt.Errorf("plan: mysql expected EOF packet, got 0x%02x", eof[0])
	}

	// Read row packets until EOF
	var jsonText string
	for {
		row, err := readMySQLPacket(r)
		if err != nil {
			return nil, fmt.Errorf("plan: mysql reading row: %w", err)
		}
		if len(row) == 0 {
			continue
		}
		// EOF packet terminates rows
		if row[0] == 0xfe && len(row) < 9 {
			break
		}
		// ERR packet
		if row[0] == 0xff {
			return nil, fmt.Errorf("plan: mysql row error: %s", mysqlErrorMessage(row))
		}
		// Extract first column text (length-encoded string)
		if jsonText == "" {
			val, _, err := readLenEncString(row, 0)
			if err == nil {
				jsonText = val
			}
		}
	}

	return parseMySQLExplainJSON(jsonText)
}

// readMySQLPacket reads one MySQL packet and returns the payload bytes.
func readMySQLPacket(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if length == 0 {
		return []byte{}, nil
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// readLenEnc reads a length-encoded integer from buf at offset off.
// Returns value, new offset, error.
func readLenEnc(buf []byte, off int) (uint64, int, error) {
	if off >= len(buf) {
		return 0, off, fmt.Errorf("plan: mysql buffer underflow")
	}
	b := buf[off]
	off++
	switch {
	case b < 0xfb:
		return uint64(b), off, nil
	case b == 0xfc:
		if off+2 > len(buf) {
			return 0, off, fmt.Errorf("plan: mysql buffer underflow (2-byte)")
		}
		v := uint64(buf[off]) | uint64(buf[off+1])<<8
		return v, off + 2, nil
	case b == 0xfd:
		if off+3 > len(buf) {
			return 0, off, fmt.Errorf("plan: mysql buffer underflow (3-byte)")
		}
		v := uint64(buf[off]) | uint64(buf[off+1])<<8 | uint64(buf[off+2])<<16
		return v, off + 3, nil
	case b == 0xfe:
		if off+8 > len(buf) {
			return 0, off, fmt.Errorf("plan: mysql buffer underflow (8-byte)")
		}
		v := binary.LittleEndian.Uint64(buf[off:])
		return v, off + 8, nil
	default:
		return 0, off, fmt.Errorf("plan: mysql NULL length-encoded int (0x%02x)", b)
	}
}

// readLenEncString reads a length-encoded string from buf at offset off.
func readLenEncString(buf []byte, off int) (string, int, error) {
	if off >= len(buf) {
		return "", off, fmt.Errorf("plan: mysql buffer underflow for string")
	}
	// NULL value
	if buf[off] == 0xfb {
		return "", off + 1, nil
	}
	length, newOff, err := readLenEnc(buf, off)
	if err != nil {
		return "", newOff, err
	}
	end := newOff + int(length)
	if end > len(buf) {
		return "", end, fmt.Errorf("plan: mysql string extends beyond packet")
	}
	return string(buf[newOff:end]), end, nil
}

// mysqlErrorMessage extracts the human-readable message from an ERR packet.
// ERR packet: 0xff + 2-byte error code + (if ≥4.1: '#' + 5-byte sqlstate) + message
func mysqlErrorMessage(pkt []byte) string {
	if len(pkt) < 3 {
		return "unknown error"
	}
	off := 3 // skip 0xff + 2-byte error code
	if off < len(pkt) && pkt[off] == '#' {
		off += 6 // skip '#' + 5-char SQLSTATE
	}
	if off < len(pkt) {
		return string(pkt[off:])
	}
	return "unknown error"
}

// mysqlExplainOutput is the top-level structure of MySQL EXPLAIN FORMAT=JSON.
// {"query_block": {"cost_info": {"query_cost": "123.45"}, ...}}
type mysqlExplainOutput struct {
	QueryBlock struct {
		CostInfo struct {
			QueryCost string `json:"query_cost"`
		} `json:"cost_info"`
	} `json:"query_block"`
}

// parseMySQLExplainJSON parses the JSON output from MySQL EXPLAIN FORMAT=JSON.
func parseMySQLExplainJSON(raw string) (*Result, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("plan: mysql empty EXPLAIN output")
	}

	var out mysqlExplainOutput
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("plan: mysql parsing EXPLAIN JSON: %w", err)
	}

	costStr := out.QueryBlock.CostInfo.QueryCost
	if costStr == "" {
		return nil, fmt.Errorf("plan: mysql EXPLAIN missing query_cost")
	}

	var cost float64
	if _, err := fmt.Sscanf(costStr, "%f", &cost); err != nil {
		return nil, fmt.Errorf("plan: mysql parsing query_cost %q: %w", costStr, err)
	}

	return &Result{TotalCost: cost}, nil
}
