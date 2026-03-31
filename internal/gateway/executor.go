package gateway

import (
	"context"
	"fmt"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/policy"
	"github.com/ersinkoc/argus/internal/pool"
	pg "github.com/ersinkoc/argus/internal/protocol/pg"
)

// ColumnMeta describes a result column.
type ColumnMeta struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

// RawResult holds the collected result of a SQL execution.
type RawResult struct {
	Columns    []ColumnMeta
	Rows       [][]any
	RowCount   int64
	MaskedCols []string
}

// executePG runs a SQL query against a PostgreSQL backend via Simple Query protocol.
// maskRules and piiDetector are optional — if provided, masking is applied after
// columns are known (from RowDescription).
func executePG(ctx context.Context, pl *pool.Pool, sql string, maxRows int64, maskRules []policy.MaskingRule, piiDetector *masking.PIIDetector, piiAutoDetect bool) (*RawResult, error) {
	conn, err := pl.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("pool acquire: %w", err)
	}
	defer pl.Release(conn)

	nc := conn.NetConn()
	result := &RawResult{}

	// Send Simple Query
	queryMsg := pg.BuildSimpleQuery(sql)
	if _, err := nc.Write(pg.EncodeMessage(queryMsg)); err != nil {
		return nil, fmt.Errorf("sending query: %w", err)
	}

	// Read result messages
	var columns []pg.ColumnDesc
	var colNames []string
	var pipeline *masking.Pipeline

	for {
		msg, err := pg.ReadMessage(nc)
		if err != nil {
			return nil, fmt.Errorf("reading result: %w", err)
		}

		switch msg.Type {
		case pg.MsgRowDescription:
			columns, err = pg.ParseRowDescription(msg.Payload)
			if err != nil {
				return nil, fmt.Errorf("parsing row description: %w", err)
			}
			colNames = make([]string, len(columns))
			colInfos := make([]masking.ColumnInfo, len(columns))
			for i, c := range columns {
				result.Columns = append(result.Columns, ColumnMeta{
					Name: c.Name,
					Type: pgTypeName(c.TypeOID),
				})
				colNames[i] = c.Name
				colInfos[i] = masking.ColumnInfo{Name: c.Name, Index: i}
			}

			// Create masking pipeline now that we know the columns
			if len(maskRules) > 0 {
				pipeline = masking.NewPipeline(maskRules, colInfos, maxRows)
				if piiDetector != nil && piiAutoDetect {
					pipeline.SetPIIDetector(piiDetector)
					pipeline.ApplyPIIDetection(colInfos)
				}
			} else if piiDetector != nil && piiAutoDetect {
				// PII auto-detect only (no explicit mask rules)
				pipeline = masking.NewPipeline(nil, colInfos, maxRows)
				pipeline.SetPIIDetector(piiDetector)
				pipeline.ApplyPIIDetection(colInfos)
			}

		case pg.MsgDataRow:
			if maxRows > 0 && result.RowCount >= maxRows {
				continue // skip but keep reading until ReadyForQuery
			}

			fields, err := pg.ParseDataRow(msg.Payload)
			if err != nil {
				return nil, fmt.Errorf("parsing data row: %w", err)
			}

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
				// Track which columns were masked
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

		case pg.MsgCommandComplete:
			// Query completed

		case pg.MsgReadyForQuery:
			return result, nil

		case pg.MsgErrorResponse:
			errFields := pg.ParseErrorResponse(msg.Payload)
			return nil, fmt.Errorf("SQL error %s: %s", errFields['C'], errFields['M'])

		case pg.MsgEmptyQuery:
			// Empty query, continue to ReadyForQuery

		default:
			// Skip NoticeResponse, ParameterStatus, etc.
		}
	}
}

// pgTypeName returns a human-readable type name for common PG OIDs.
func pgTypeName(oid int32) string {
	switch oid {
	case 16:
		return "bool"
	case 20:
		return "int8"
	case 21:
		return "int2"
	case 23:
		return "int4"
	case 25:
		return "text"
	case 700:
		return "float4"
	case 701:
		return "float8"
	case 1042:
		return "bpchar"
	case 1043:
		return "varchar"
	case 1082:
		return "date"
	case 1114:
		return "timestamp"
	case 1184:
		return "timestamptz"
	case 1700:
		return "numeric"
	case 2950:
		return "uuid"
	default:
		return fmt.Sprintf("oid:%d", oid)
	}
}

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
