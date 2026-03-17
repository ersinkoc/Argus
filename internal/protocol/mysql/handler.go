package mysql

import (
	"context"
	"fmt"
	"net"

	"github.com/ersinkoc/argus/internal/inspection"
	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/protocol"
	"github.com/ersinkoc/argus/internal/session"
)

// Handler implements protocol.Handler for MySQL.
type Handler struct {
	stmtStore *StmtStore // tracks prepared statements per connection
}

// New creates a new MySQL protocol handler.
func New() *Handler {
	return &Handler{
		stmtStore: NewStmtStore(),
	}
}

func (h *Handler) Name() string {
	return "mysql"
}

// DetectProtocol checks for MySQL protocol.
// MySQL is server-speaks-first, so detection is by port configuration.
func (h *Handler) DetectProtocol(peek []byte) bool {
	// MySQL server sends the greeting first, so client-side detection
	// isn't typical. We rely on listener port config instead.
	return false
}

// Handshake performs MySQL authentication passthrough.
func (h *Handler) Handshake(ctx context.Context, client, backend net.Conn) (*session.Info, error) {
	// Step 1: Read greeting from backend
	greeting, err := ReadPacket(backend)
	if err != nil {
		return nil, fmt.Errorf("reading backend greeting: %w", err)
	}

	// Forward greeting to client
	if err := WritePacket(client, greeting); err != nil {
		return nil, fmt.Errorf("forwarding greeting: %w", err)
	}

	// Step 2: Read client's handshake response
	response, err := ReadPacket(client)
	if err != nil {
		return nil, fmt.Errorf("reading client handshake: %w", err)
	}

	// Parse to extract username and database
	handshake, err := ParseHandshakeResponse41(response.Payload)
	if err != nil {
		return nil, fmt.Errorf("parsing handshake response: %w", err)
	}

	// Forward to backend
	if err := WritePacket(backend, response); err != nil {
		return nil, fmt.Errorf("forwarding handshake to backend: %w", err)
	}

	// Step 3: Read auth result from backend
	authResult, err := ReadPacket(backend)
	if err != nil {
		return nil, fmt.Errorf("reading auth result: %w", err)
	}

	// Forward to client
	if err := WritePacket(client, authResult); err != nil {
		return nil, fmt.Errorf("forwarding auth result: %w", err)
	}

	// Check if auth succeeded
	if len(authResult.Payload) > 0 && authResult.Payload[0] == 0xFF {
		return nil, fmt.Errorf("backend auth failed")
	}

	// Handle auth switch or additional auth packets
	// MySQL 8 caching_sha2_password sends:
	//   0x01 0x04 = fast auth success (AuthMoreData with status 0x04)
	//   0x01 0x03 = full auth needed
	//   0xFE      = auth switch request
	for len(authResult.Payload) > 0 && authResult.Payload[0] != 0x00 && authResult.Payload[0] != 0xFF {
		// Check for AuthMoreData with fast auth success (0x01 + 0x04)
		if authResult.Payload[0] == 0x01 && len(authResult.Payload) >= 2 && authResult.Payload[1] == 0x04 {
			// Fast auth success — next packet from backend is the final OK
			authResult, err = ReadPacket(backend)
			if err != nil {
				return nil, fmt.Errorf("reading final auth OK: %w", err)
			}
			if err := WritePacket(client, authResult); err != nil {
				return nil, fmt.Errorf("forwarding final auth OK: %w", err)
			}
			break
		}

		// Auth continuation — forward bidirectionally
		clientResp, err := ReadPacket(client)
		if err != nil {
			return nil, fmt.Errorf("reading auth continuation: %w", err)
		}
		if err := WritePacket(backend, clientResp); err != nil {
			return nil, fmt.Errorf("forwarding auth continuation: %w", err)
		}
		authResult, err = ReadPacket(backend)
		if err != nil {
			return nil, fmt.Errorf("reading auth continuation result: %w", err)
		}
		if err := WritePacket(client, authResult); err != nil {
			return nil, fmt.Errorf("forwarding auth continuation result: %w", err)
		}
	}

	info := &session.Info{
		Username:   handshake.Username,
		Database:   handshake.Database,
		AuthMethod: "mysql_native_password",
	}

	return info, nil
}

// ReadCommand reads the next command from the MySQL client.
func (h *Handler) ReadCommand(ctx context.Context, client net.Conn) (*inspection.Command, []byte, error) {
	pkt, err := ReadPacket(client)
	if err != nil {
		return nil, nil, fmt.Errorf("reading client command: %w", err)
	}

	if len(pkt.Payload) == 0 {
		return nil, EncodePacket(pkt), nil
	}

	cmdByte := pkt.Payload[0]
	switch cmdByte {
	case ComQuery:
		sql := string(pkt.Payload[1:])
		cmd := inspection.Classify(sql)
		return cmd, EncodePacket(pkt), nil

	case ComQuit:
		return nil, EncodePacket(pkt), nil

	case ComPing:
		cmd := &inspection.Command{
			Type:      inspection.CommandADMIN,
			Raw:       "[PING]",
			RiskLevel: inspection.RiskNone,
		}
		return cmd, EncodePacket(pkt), nil

	case ComInitDB:
		dbName := string(pkt.Payload[1:])
		cmd := &inspection.Command{
			Type:      inspection.CommandADMIN,
			Raw:       fmt.Sprintf("USE %s", dbName),
			RiskLevel: inspection.RiskNone,
		}
		return cmd, EncodePacket(pkt), nil

	case ComStmtPrepare:
		// Extract SQL from COM_STMT_PREPARE for inspection
		sql := string(pkt.Payload[1:])
		cmd := inspection.Classify(sql)
		cmd.Confidence = 0.8 // prepared statement, no param values yet
		return cmd, EncodePacket(pkt), nil

	case ComStmtExecute:
		// Look up SQL from stored prepared statement
		stmtID, sql := HandleExecute(pkt, h.stmtStore)
		cmd := &inspection.Command{
			Type:       inspection.CommandUNKNOWN,
			Raw:        sql,
			RiskLevel:  inspection.RiskNone,
			Confidence: 0.5,
		}
		if sql != "" {
			cmd = inspection.Classify(sql)
			cmd.Confidence = 0.5
		}
		_ = stmtID
		return cmd, EncodePacket(pkt), nil

	case ComStmtClose:
		HandleClose(pkt, h.stmtStore)
		cmd := &inspection.Command{
			Type:      inspection.CommandADMIN,
			Raw:       "[STMT_CLOSE]",
			RiskLevel: inspection.RiskNone,
		}
		return cmd, EncodePacket(pkt), nil

	case ComStmtReset:
		cmd := &inspection.Command{
			Type:      inspection.CommandADMIN,
			Raw:       "[STMT_RESET]",
			RiskLevel: inspection.RiskNone,
		}
		return cmd, EncodePacket(pkt), nil

	default:
		cmd := &inspection.Command{
			Type:      inspection.CommandUNKNOWN,
			Raw:       fmt.Sprintf("[mysql_cmd=0x%02x]", cmdByte),
			RiskLevel: inspection.RiskNone,
		}
		return cmd, EncodePacket(pkt), nil
	}
}

// RebuildQuery rebuilds a COM_QUERY packet with a new SQL string.
func (h *Handler) RebuildQuery(rawMsg []byte, newSQL string) []byte {
	payload := append([]byte{ComQuery}, []byte(newSQL)...)
	pkt := &Packet{SequenceID: 0, Payload: payload}
	return EncodePacket(pkt)
}

// ForwardCommand sends raw command bytes to the backend.
func (h *Handler) ForwardCommand(ctx context.Context, rawMsg []byte, backend net.Conn) error {
	_, err := backend.Write(rawMsg)
	return err
}

// ReadAndForwardResult reads MySQL result set from backend and writes to client.
func (h *Handler) ReadAndForwardResult(ctx context.Context, backend, client net.Conn, pipeline *masking.Pipeline) (*protocol.ResultStats, error) {
	stats := &protocol.ResultStats{}

	// Read first packet (column count or OK/ERR)
	pkt, err := ReadPacket(backend)
	if err != nil {
		return stats, fmt.Errorf("reading result header: %w", err)
	}

	// OK packet
	if len(pkt.Payload) > 0 && pkt.Payload[0] == 0x00 {
		return stats, WritePacket(client, pkt)
	}

	// ERR packet
	if len(pkt.Payload) > 0 && pkt.Payload[0] == 0xFF {
		return stats, WritePacket(client, pkt)
	}

	// Result set: first byte is column count (length-encoded integer)
	columnCount := int(pkt.Payload[0])
	if err := WritePacket(client, pkt); err != nil {
		return stats, err
	}

	// Column definitions
	var colNames []string
	for i := 0; i < columnCount; i++ {
		colPkt, err := ReadPacket(backend)
		if err != nil {
			return stats, fmt.Errorf("reading column def %d: %w", i, err)
		}
		colNames = append(colNames, extractColumnName(colPkt.Payload))
		if err := WritePacket(client, colPkt); err != nil {
			return stats, err
		}
	}

	// EOF after column definitions (deprecated but still common)
	eofPkt, err := ReadPacket(backend)
	if err != nil {
		return stats, fmt.Errorf("reading column EOF: %w", err)
	}
	if err := WritePacket(client, eofPkt); err != nil {
		return stats, err
	}

	// Set up masking pipeline with column names
	if pipeline != nil && len(colNames) > 0 {
		colInfos := make([]masking.ColumnInfo, len(colNames))
		for i, name := range colNames {
			colInfos[i] = masking.ColumnInfo{Name: name, Index: i}
		}
		*pipeline = *masking.NewPipeline(pipeline.MaskingRules(), colInfos, pipeline.MaxRowsLimit())
	}

	// Rows
	for {
		rowPkt, err := ReadPacket(backend)
		if err != nil {
			return stats, fmt.Errorf("reading row: %w", err)
		}

		// EOF or ERR = end of rows
		if len(rowPkt.Payload) > 0 && (rowPkt.Payload[0] == 0xFE || rowPkt.Payload[0] == 0xFF) {
			if err := WritePacket(client, rowPkt); err != nil {
				return stats, err
			}
			break
		}

		stats.RowCount++

		// Apply masking if pipeline is set up
		if pipeline != nil && pipeline.HasMasking() {
			fields := parseMySQLTextRow(rowPkt.Payload, columnCount)
			maskFields := make([]masking.FieldValue, len(fields))
			for i, f := range fields {
				if f == nil {
					maskFields[i] = masking.FieldValue{IsNull: true}
				} else {
					maskFields[i] = masking.FieldValue{Data: f}
				}
			}

			masked, include := pipeline.ProcessRow(maskFields)
			if !include {
				stats.Truncated = true
				continue
			}

			// Rebuild row packet
			rowPkt.Payload = buildMySQLTextRow(masked)
		}

		if err := WritePacket(client, rowPkt); err != nil {
			return stats, err
		}
	}

	if pipeline != nil {
		stats.MaskedCols = pipeline.MaskedColumns()
		stats.Truncated = pipeline.IsTruncated()
	}

	return stats, nil
}

// WriteError sends a MySQL error to the client.
func (h *Handler) WriteError(ctx context.Context, client net.Conn, code string, message string) error {
	errPkt := BuildErrPacket(1, 1045, message)
	return WritePacket(client, errPkt)
}

func (h *Handler) Close() error {
	return nil
}

// extractColumnName extracts the column name from a column definition packet.
// MySQL column definition format (COM_QUERY response):
// catalog, schema, table, org_table, name, org_name, ...
func extractColumnName(payload []byte) string {
	i := 0
	// Skip 4 length-encoded strings: catalog, schema, table, org_table
	for skip := 0; skip < 4; skip++ {
		if i >= len(payload) {
			return ""
		}
		strLen := int(payload[i])
		i += 1 + strLen
	}
	// Read name
	if i >= len(payload) {
		return ""
	}
	nameLen := int(payload[i])
	i++
	if i+nameLen > len(payload) {
		return ""
	}
	return string(payload[i : i+nameLen])
}

// parseMySQLTextRow parses a text protocol result row.
// Each field is a length-encoded string or 0xFB for NULL.
func parseMySQLTextRow(payload []byte, numCols int) [][]byte {
	fields := make([][]byte, numCols)
	i := 0
	for col := 0; col < numCols && i < len(payload); col++ {
		if payload[i] == 0xFB {
			fields[col] = nil // NULL
			i++
		} else {
			strLen := int(payload[i])
			i++
			if i+strLen <= len(payload) {
				fields[col] = payload[i : i+strLen]
				i += strLen
			}
		}
	}
	return fields
}

// buildMySQLTextRow builds a text protocol row from field values.
func buildMySQLTextRow(fields []masking.FieldValue) []byte {
	var payload []byte
	for _, f := range fields {
		if f.IsNull {
			payload = append(payload, 0xFB)
		} else {
			payload = append(payload, byte(len(f.Data)))
			payload = append(payload, f.Data...)
		}
	}
	return payload
}
