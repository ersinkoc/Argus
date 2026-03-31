package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/pool"
	mysql "github.com/ersinkoc/argus/internal/protocol/mysql"
)

// executeMySQL runs a SQL query against a MySQL backend via COM_QUERY.
func executeMySQL(ctx context.Context, pl *pool.Pool, sql string, maxRows int64, maskRules []policy.MaskingRule, piiDetector *masking.PIIDetector, piiAutoDetect bool) (*RawResult, error) {
	conn, err := pl.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("pool acquire: %w", err)
	}

	var success bool
	defer func() {
		if success {
			pl.Release(conn)
		} else {
			pl.Remove(conn)
		}
	}()

	nc := conn.NetConn()

	if deadline, ok := ctx.Deadline(); ok {
		nc.SetDeadline(deadline)
	} else {
		nc.SetDeadline(time.Now().Add(30 * time.Second))
	}
	defer nc.SetDeadline(time.Time{})

	result := &RawResult{}

	// Send COM_QUERY
	payload := append([]byte{mysql.ComQuery}, []byte(sql)...)
	pkt := &mysql.Packet{SequenceID: 0, Payload: payload}
	if err := mysql.WritePacket(nc, pkt); err != nil {
		return nil, fmt.Errorf("sending query: %w", err)
	}

	// Read first response packet
	resp, err := mysql.ReadPacket(nc)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if len(resp.Payload) == 0 {
		return nil, fmt.Errorf("empty response from backend")
	}

	// Check for ERR packet
	if resp.Payload[0] == 0xFF {
		errMsg := "unknown error"
		if len(resp.Payload) > 9 {
			errMsg = string(resp.Payload[9:]) // skip err_code(2) + '#' + state(5)
		}
		return nil, fmt.Errorf("SQL error: %s", errMsg)
	}

	// Check for OK packet (non-SELECT: INSERT, UPDATE, DELETE, DDL)
	if resp.Payload[0] == 0x00 {
		success = true
		return result, nil
	}

	// Result set: first byte is column count
	columnCount := int(resp.Payload[0])

	// Read column definitions
	colNames := make([]string, columnCount)
	colInfos := make([]masking.ColumnInfo, columnCount)
	for i := 0; i < columnCount; i++ {
		colPkt, err := mysql.ReadPacket(nc)
		if err != nil {
			return nil, fmt.Errorf("reading column definition %d: %w", i, err)
		}
		name := mysql.ExtractColumnName(colPkt.Payload)
		colNames[i] = name
		colInfos[i] = masking.ColumnInfo{Name: name, Index: i}
		result.Columns = append(result.Columns, ColumnMeta{Name: name})
	}

	// Read EOF after column definitions
	if _, err := mysql.ReadPacket(nc); err != nil {
		return nil, fmt.Errorf("reading column EOF: %w", err)
	}

	// Create masking pipeline if needed
	var pipeline *masking.Pipeline
	if len(maskRules) > 0 {
		pipeline = masking.NewPipeline(maskRules, colInfos, maxRows)
		if piiDetector != nil && piiAutoDetect {
			pipeline.SetPIIDetector(piiDetector)
			pipeline.ApplyPIIDetection(colInfos)
		}
	} else if piiDetector != nil && piiAutoDetect {
		pipeline = masking.NewPipeline(nil, colInfos, maxRows)
		pipeline.SetPIIDetector(piiDetector)
		pipeline.ApplyPIIDetection(colInfos)
	}

	// Read rows until EOF or ERR
	for {
		rowPkt, err := mysql.ReadPacket(nc)
		if err != nil {
			return nil, fmt.Errorf("reading row: %w", err)
		}

		// EOF or ERR packet ends the result set
		if len(rowPkt.Payload) > 0 && (rowPkt.Payload[0] == 0xFE || rowPkt.Payload[0] == 0xFF) {
			break
		}

		if maxRows > 0 && result.RowCount >= maxRows {
			continue // skip but keep reading until EOF
		}

		fields := mysql.ParseMySQLTextRow(rowPkt.Payload, columnCount)

		if pipeline != nil {
			maskFields := make([]masking.FieldValue, len(fields))
			for i, f := range fields {
				if f == nil {
					maskFields[i] = masking.FieldValue{IsNull: true}
				} else {
					maskFields[i] = masking.FieldValue{Data: f}
				}
			}
			masked, _ := pipeline.ProcessRow(maskFields)
			for i, mf := range masked {
				if i < len(fields) && fields[i] != nil && string(mf.Data) != string(fields[i]) {
					if i < len(colNames) {
						result.MaskedCols = appendUnique(result.MaskedCols, colNames[i])
					}
				}
			}
			row := make([]any, len(masked))
			for i, mf := range masked {
				if mf.IsNull {
					row[i] = nil
				} else {
					row[i] = string(mf.Data)
				}
			}
			result.Rows = append(result.Rows, row)
		} else {
			row := make([]any, len(fields))
			for i, f := range fields {
				if f == nil {
					row[i] = nil
				} else {
					row[i] = string(f)
				}
			}
			result.Rows = append(result.Rows, row)
		}
		result.RowCount++
	}

	success = true
	return result, nil
}
