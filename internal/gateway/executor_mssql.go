package gateway

import (
	"context"
	"fmt"
	"time"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/pool"
	mssql "github.com/ersinkoc/argus/internal/protocol/mssql"
)

// executeMSSQL runs a SQL query against an MSSQL backend via a TDS SQL Batch
// and parses the COLMETADATA/ROW/DONE token stream from the reply.
func executeMSSQL(ctx context.Context, pl *pool.Pool, sql string, maxRows int64, maskRules []policy.MaskingRule, piiDetector *masking.PIIDetector, piiAutoDetect bool) (*RawResult, error) {
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

	// Send the query as a TDS SQL Batch (ALL_HEADERS with total length 4 = none).
	batch := append([]byte{4, 0, 0, 0}, mssql.EncodeUTF16LE(sql)...)
	if err := mssql.WritePacket(nc, &mssql.Packet{Type: mssql.PacketSQLBatch, Status: mssql.StatusEOM, Data: batch}); err != nil {
		return nil, fmt.Errorf("sending query: %w", err)
	}

	// Reassemble the full reply token stream (may span multiple TDS packets).
	data, replyType, err := mssql.ReadAllPackets(nc)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if replyType != mssql.PacketReply {
		return nil, fmt.Errorf("unexpected TDS reply type 0x%02x", replyType)
	}

	result := &RawResult{}
	var columns []mssql.TDSColumnMeta
	var pipeline *masking.Pipeline

	offset := 0
	for offset < len(data) {
		token := data[offset]
		switch token {
		case mssql.TokenColMetadata:
			cols, consumed := mssql.ParseColMetadata(data[offset:])
			if consumed <= 0 {
				return nil, fmt.Errorf("malformed COLMETADATA token")
			}
			columns = cols
			colInfos := make([]masking.ColumnInfo, len(cols))
			for i, c := range cols {
				result.Columns = append(result.Columns, ColumnMeta{Name: c.Name, Type: tdsTypeName(c.TypeID)})
				colInfos[i] = masking.ColumnInfo{Name: c.Name, Index: i}
			}
			pipeline = buildMSSQLPipeline(maskRules, colInfos, maxRows, piiDetector, piiAutoDetect)
			if pipeline != nil {
				result.MaskedCols = maskedTextColumns(cols, pipeline)
			}
			offset += consumed

		case mssql.TokenRow, mssql.TokenNBCRow:
			rowLen := mssql.TDSRowLen(data[offset:], columns)
			if rowLen <= 0 {
				// Cannot determine the row boundary; stop to avoid misparsing.
				offset = len(data)
				break
			}
			rowToken := data[offset : offset+rowLen]
			if maxRows <= 0 || result.RowCount < maxRows {
				if pipeline != nil && pipeline.HasMasking() {
					rowToken = mssql.MaskTDSRow(rowToken, columns, pipeline)
				}
				result.Rows = append(result.Rows, mssql.ExtractTDSRowValues(rowToken, columns))
			}
			result.RowCount++
			offset += rowLen

		case mssql.TokenError:
			msg := mssql.ParseErrorTokenMessage(data[offset:])
			return nil, fmt.Errorf("SQL error: %s", msg)

		default:
			consumed := mssql.TDSTokenLen(data[offset:])
			if consumed <= 0 {
				offset = len(data) // unknown token; stop cleanly
				break
			}
			offset += consumed
		}
	}

	success = true
	return result, nil
}

func buildMSSQLPipeline(maskRules []policy.MaskingRule, colInfos []masking.ColumnInfo, maxRows int64, piiDetector *masking.PIIDetector, piiAutoDetect bool) *masking.Pipeline {
	if len(maskRules) > 0 {
		p := masking.NewPipeline(maskRules, colInfos, maxRows)
		if piiDetector != nil && piiAutoDetect {
			p.SetPIIDetector(piiDetector)
			p.ApplyPIIDetection(colInfos)
		}
		return p
	}
	if piiDetector != nil && piiAutoDetect {
		p := masking.NewPipeline(nil, colInfos, maxRows)
		p.SetPIIDetector(piiDetector)
		p.ApplyPIIDetection(colInfos)
		return p
	}
	return nil
}

// maskedTextColumns returns the names of text columns the pipeline is
// configured to mask. TDS masking rewrites values in place, so — unlike the
// PG/MySQL paths that diff pre/post bytes — masked-column identity is taken
// from the pipeline's active rule set (explicit rules plus PII auto-detection)
// intersected with the text columns TDS masking can actually rewrite.
func maskedTextColumns(columns []mssql.TDSColumnMeta, pipeline *masking.Pipeline) []string {
	masked := pipeline.MaskedColumns()
	if len(masked) == 0 {
		return nil
	}
	inMasked := make(map[string]bool, len(masked))
	for _, name := range masked {
		inMasked[name] = true
	}
	var out []string
	for _, c := range columns {
		if c.IsText && inMasked[c.Name] {
			out = appendUnique(out, c.Name)
		}
	}
	return out
}

// tdsTypeName returns a short name for common TDS type IDs.
func tdsTypeName(typeID byte) string {
	switch typeID {
	case 0x30:
		return "tinyint"
	case 0x32:
		return "bit"
	case 0x34:
		return "smallint"
	case 0x38:
		return "int"
	case 0x3D:
		return "datetime"
	case 0x3E:
		return "float"
	case 0x7F:
		return "bigint"
	case 0xA5:
		return "varbinary"
	case 0xAD:
		return "varchar"
	case 0xE7:
		return "nvarchar"
	case 0xEF:
		return "nchar"
	default:
		return fmt.Sprintf("type:0x%02x", typeID)
	}
}
