package pg

import (
	"context"
	"fmt"
	"net"

	"github.com/ersinkoc/argus/internal/masking"
	"github.com/ersinkoc/argus/internal/protocol"
)

// ForwardResult reads results from the backend and writes them to the client,
// optionally applying masking transformations.
func ForwardResult(ctx context.Context, backend, client net.Conn, pipeline *masking.Pipeline) (*protocol.ResultStats, error) {
	stats := &protocol.ResultStats{}
	var columns []ColumnDesc

	for {
		select {
		case <-ctx.Done():
			return stats, ctx.Err()
		default:
		}

		msg, err := ReadMessage(backend)
		if err != nil {
			return stats, fmt.Errorf("reading backend result: %w", err)
		}

		switch msg.Type {
		case MsgRowDescription:
			// Parse column info for masking pipeline setup
			var parseErr error
			columns, parseErr = ParseRowDescription(msg.Payload)
			if parseErr != nil {
				// Forward as-is if we can't parse
				if err := WriteMessage(client, msg); err != nil {
					return stats, fmt.Errorf("forwarding RowDescription: %w", err)
				}
				continue
			}

			// Set up masking pipeline with column info if needed
			if pipeline != nil && len(columns) > 0 {
				colInfos := make([]masking.ColumnInfo, len(columns))
				for i, c := range columns {
					colInfos[i] = masking.ColumnInfo{Name: c.Name, Index: i}
				}
				*pipeline = *masking.NewPipeline(pipeline.MaskingRules(), colInfos, pipeline.MaxRowsLimit())

				// PII auto-detection on column names
				pipeline.ApplyPIIDetection(colInfos)
			}

			// Forward RowDescription to client
			if err := WriteMessage(client, msg); err != nil {
				return stats, fmt.Errorf("forwarding RowDescription: %w", err)
			}

		case MsgDataRow:
			stats.RowCount++
			stats.ByteCount += int64(len(msg.Payload) + 5) // type + length + payload

			if pipeline != nil && pipeline.HasMasking() {
				// Parse the data row
				fields, err := ParseDataRow(msg.Payload)
				if err != nil {
					// Can't parse, forward as-is
					if err := WriteMessage(client, msg); err != nil {
						return stats, fmt.Errorf("forwarding DataRow: %w", err)
					}
					continue
				}

				// Convert to masking field values
				maskFields := make([]masking.FieldValue, len(fields))
				for i, f := range fields {
					if f == nil {
						maskFields[i] = masking.FieldValue{IsNull: true}
					} else {
						maskFields[i] = masking.FieldValue{Data: f}
					}
				}

				// Apply masking
				maskedFields, include := pipeline.ProcessRow(maskFields)
				if !include {
					stats.Truncated = true
					continue // skip row (row limit exceeded)
				}

				// Convert back to raw fields
				rawFields := make([][]byte, len(maskedFields))
				for i, f := range maskedFields {
					if f.IsNull {
						rawFields[i] = nil
					} else {
						rawFields[i] = f.Data
					}
				}

				// Build new DataRow message
				maskedMsg := BuildDataRow(rawFields)
				if err := WriteMessage(client, maskedMsg); err != nil {
					return stats, fmt.Errorf("forwarding masked DataRow: %w", err)
				}
			} else {
				// No masking, forward as-is
				if err := WriteMessage(client, msg); err != nil {
					return stats, fmt.Errorf("forwarding DataRow: %w", err)
				}
			}

		case MsgCommandComplete:
			// Forward command complete
			if err := WriteMessage(client, msg); err != nil {
				return stats, fmt.Errorf("forwarding CommandComplete: %w", err)
			}

		case MsgReadyForQuery:
			// Query cycle complete, forward and return
			if err := WriteMessage(client, msg); err != nil {
				return stats, fmt.Errorf("forwarding ReadyForQuery: %w", err)
			}

			if pipeline != nil {
				stats.MaskedCols = pipeline.MaskedColumns()
				stats.Truncated = pipeline.IsTruncated()
			}

			return stats, nil

		case MsgErrorResponse:
			// Forward error to client
			if err := WriteMessage(client, msg); err != nil {
				return stats, fmt.Errorf("forwarding ErrorResponse: %w", err)
			}

		case MsgCopyInResponse:
			// COPY FROM STDIN — forward response, then relay client data to backend
			if err := WriteMessage(client, msg); err != nil {
				return stats, fmt.Errorf("forwarding CopyInResponse: %w", err)
			}
			if err := HandleCopyIn(ctx, client, backend); err != nil {
				return stats, fmt.Errorf("handling COPY IN: %w", err)
			}
			// Continue reading for CommandComplete + ReadyForQuery

		case MsgCopyOutResponse:
			// COPY TO STDOUT — forward response, then relay backend data to client
			if err := WriteMessage(client, msg); err != nil {
				return stats, fmt.Errorf("forwarding CopyOutResponse: %w", err)
			}
			if err := HandleCopyOut(ctx, backend, client); err != nil {
				return stats, fmt.Errorf("handling COPY OUT: %w", err)
			}
			// Continue reading for CommandComplete + ReadyForQuery

		case MsgNoticeResponse, MsgEmptyQuery, MsgNoData,
			MsgParseComplete, MsgBindComplete, MsgCloseComplete,
			MsgParameterDesc, MsgPortalSuspended:
			// Forward as-is (includes Extended Query backend responses)
			if err := WriteMessage(client, msg); err != nil {
				return stats, fmt.Errorf("forwarding message %c: %w", msg.Type, err)
			}

		default:
			// Forward unknown messages
			if err := WriteMessage(client, msg); err != nil {
				return stats, fmt.Errorf("forwarding unknown message %c: %w", msg.Type, err)
			}
		}
	}
}
