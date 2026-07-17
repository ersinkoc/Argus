package mssql

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/ersinkoc/argus/internal/masking"
)

// TDSColumnMeta holds parsed column metadata from COLMETADATA token.
type TDSColumnMeta struct {
	Name   string
	TypeID byte
	MaxLen int
	Index  int
	IsText bool // whether the column carries text data we can mask
}

// ParseColMetadata extracts column info from a COLMETADATA token in a TDS data stream.
// Format: token(0x81) + count(uint16) + [column_def...]
// Returns columns and the number of bytes consumed.
func ParseColMetadata(data []byte) ([]TDSColumnMeta, int) {
	if len(data) < 3 || data[0] != TokenColMetadata {
		return nil, 0
	}

	count := int(binary.LittleEndian.Uint16(data[1:3]))
	if count == 0xFFFF { // no metadata
		return nil, 3
	}

	offset := 3
	cols := make([]TDSColumnMeta, 0, count)

	for i := 0; i < count && offset < len(data); i++ {
		col := TDSColumnMeta{Index: i}

		// Skip user type (4 bytes) + flags (2 bytes)
		if offset+6 > len(data) {
			break
		}
		offset += 6

		// Type ID
		if offset >= len(data) {
			break
		}
		col.TypeID = data[offset]
		offset++

		// Parse type-specific length info
		// Simplified: handle common variable-length types
		switch {
		case isFixedLenType(col.TypeID):
			col.MaxLen = fixedTypeLen(col.TypeID)
		case col.TypeID == 0xA5 || col.TypeID == 0xAD: // BIGVARBIN, BIGVARCHR
			if offset+2 > len(data) {
				break
			}
			col.MaxLen = int(binary.LittleEndian.Uint16(data[offset:]))
			offset += 2
			col.IsText = col.TypeID == 0xAD
		case col.TypeID == 0xE7 || col.TypeID == 0xEF: // NVARCHAR, NCHAR
			if offset+2 > len(data) {
				break
			}
			col.MaxLen = int(binary.LittleEndian.Uint16(data[offset:]))
			offset += 2
			// Collation (5 bytes)
			if offset+5 <= len(data) {
				offset += 5
			}
			col.IsText = true
		case col.TypeID == 0x22 || col.TypeID == 0x23 || col.TypeID == 0x24: // IMAGE, TEXT, UNIQUEIDENTIFIER
			if offset+4 <= len(data) {
				col.MaxLen = int(binary.LittleEndian.Uint32(data[offset:]))
				offset += 4
			}
		default:
			// Variable length: read 1-byte length
			if offset < len(data) {
				col.MaxLen = int(data[offset])
				offset++
				col.IsText = true
			}
		}

		// Column name: B_VARCHAR (1-byte length + UTF-16LE)
		if offset >= len(data) {
			break
		}
		nameLen := int(data[offset])
		offset++
		if offset+nameLen*2 > len(data) {
			break
		}
		col.Name = decodeUTF16LESlice(data[offset : offset+nameLen*2])
		offset += nameLen * 2

		cols = append(cols, col)
	}

	return cols, offset
}

// tdsRowField is one column value located within a ROW token's byte stream.
type tdsRowField struct {
	col      TDSColumnMeta
	isText   bool // variable-length text field carrying a 2-byte length prefix
	isNull   bool
	dataFrom int // offset of the value bytes (after any length prefix)
	dataTo   int
}

// walkTDSRow parses the column values in a ROW/NBCROW token body, returning one
// entry per successfully located column. Parsing stops at the first field that
// runs past the end of data; trailing bytes past the last parsed field start at
// the returned tailOffset. This is a best-effort walk — full TDS row parsing is
// type-dependent — shared by MaskTDSRow and ExtractTDSRowValues so both agree
// on field boundaries.
func walkTDSRow(data []byte, cols []TDSColumnMeta) (fields []tdsRowField, tailOffset int) {
	if len(data) < 1 {
		return nil, len(data)
	}
	offset := 1 // skip token byte
	for _, col := range cols {
		if offset >= len(data) {
			break
		}
		if col.IsText {
			if offset+2 > len(data) {
				break
			}
			fieldLen := int(binary.LittleEndian.Uint16(data[offset:]))
			offset += 2
			if fieldLen == 0xFFFF { // NULL
				fields = append(fields, tdsRowField{col: col, isText: true, isNull: true, dataFrom: offset, dataTo: offset})
				continue
			}
			if offset+fieldLen > len(data) {
				break
			}
			fields = append(fields, tdsRowField{col: col, isText: true, dataFrom: offset, dataTo: offset + fieldLen})
			offset += fieldLen
		} else {
			fieldLen := col.MaxLen
			if fieldLen < 0 || offset+fieldLen > len(data) {
				break
			}
			fields = append(fields, tdsRowField{col: col, dataFrom: offset, dataTo: offset + fieldLen})
			offset += fieldLen
		}
	}
	return fields, offset
}

// MaskTDSRow applies masking to a ROW token's data.
// TDS ROW format: token(0xD1) + column_values...
// This is a best-effort approach — exact parsing depends on column types.
func MaskTDSRow(data []byte, cols []TDSColumnMeta, pipeline *masking.Pipeline) []byte {
	if len(data) < 1 || (data[0] != TokenRow && data[0] != TokenNBCRow) {
		return data
	}

	if pipeline == nil || !pipeline.HasMasking() {
		return data
	}

	fields, tail := walkTDSRow(data, cols)

	// Build one FieldValue per column at its true index, then mask the whole
	// row in a single ProcessRow call so each column's transformer is applied
	// by index (a per-field call would only ever apply column 0's rule and
	// would inflate the pipeline's row counter). N-type columns store UTF-16LE
	// on the wire; decode to plain text before masking so the transformers see
	// characters, not raw code units.
	row := make([]masking.FieldValue, len(fields))
	for i, f := range fields {
		if f.isNull {
			row[i] = masking.FieldValue{IsNull: true}
			continue
		}
		raw := data[f.dataFrom:f.dataTo]
		if isNTextType(f.col.TypeID) {
			row[i] = masking.FieldValue{Data: []byte(decodeUTF16LESlice(raw))}
		} else {
			row[i] = masking.FieldValue{Data: raw}
		}
	}
	masked, _ := pipeline.ProcessRow(row)

	result := make([]byte, 0, len(data))
	result = append(result, data[0]) // token byte

	for i, f := range fields {
		if f.isText {
			if f.isNull {
				// Re-emit the 2-byte NULL length prefix (0xFFFF).
				result = append(result, data[f.dataFrom-2:f.dataFrom]...)
				continue
			}
			fieldData := data[f.dataFrom:f.dataTo]
			if i < len(masked) && !masked[i].IsNull {
				if isNTextType(f.col.TypeID) {
					fieldData = toUTF16LE(string(masked[i].Data))
				} else {
					fieldData = masked[i].Data
				}
			}
			lenBuf := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenBuf, uint16(len(fieldData)))
			result = append(result, lenBuf...)
			result = append(result, fieldData...)
		} else {
			// Fixed-length: copy as-is.
			result = append(result, data[f.dataFrom:f.dataTo]...)
		}
	}

	// Append any remaining data past the last parsed field.
	if tail < len(data) {
		result = append(result, data[tail:]...)
	}

	return result
}

// ExtractTDSRowValues returns the per-column values of a ROW/NBCROW token as
// strings (nil for NULL). Text columns are decoded from UTF-16LE when the type
// is an N-type (NVARCHAR/NCHAR); other text is returned as-is. Fixed-length and
// unparsed columns yield the raw bytes as a string. Best-effort — mirrors the
// field boundaries used by MaskTDSRow.
func ExtractTDSRowValues(data []byte, cols []TDSColumnMeta) []any {
	if len(data) < 1 || (data[0] != TokenRow && data[0] != TokenNBCRow) {
		return nil
	}
	fields, _ := walkTDSRow(data, cols)
	values := make([]any, 0, len(fields))
	for _, f := range fields {
		if f.isNull {
			values = append(values, nil)
			continue
		}
		raw := data[f.dataFrom:f.dataTo]
		if f.isText && (f.col.TypeID == 0xE7 || f.col.TypeID == 0xEF) {
			values = append(values, decodeUTF16LESlice(raw))
		} else {
			values = append(values, string(raw))
		}
	}
	return values
}

// EncodeUTF16LE encodes a string to UTF-16LE bytes, matching the on-wire
// encoding TDS uses for SQL Batch payloads and string tokens.
func EncodeUTF16LE(s string) []byte {
	return toUTF16LE(s)
}

// TDSRowLen returns the total byte length of the ROW/NBCROW token at the start
// of data, given the column metadata, or 0 if the row cannot be located.
func TDSRowLen(data []byte, cols []TDSColumnMeta) int {
	if len(data) < 1 || (data[0] != TokenRow && data[0] != TokenNBCRow) {
		return 0
	}
	fields, tail := walkTDSRow(data, cols)
	if len(fields) < len(cols) {
		// A field ran past the end of data — the row is truncated or a column
		// type we cannot size. Signal "unknown" so callers stop cleanly.
		return 0
	}
	return tail
}

// TDSTokenLen returns the byte length of the length-prefixed or fixed-length
// token at the start of data, for the token types that appear in a SQL Batch
// reply stream. It returns 0 for ROW/NBCROW/COLMETADATA (which need column
// context to size) and for any unrecognized token, so callers can stop cleanly
// rather than misparse.
func TDSTokenLen(data []byte) int {
	if len(data) < 1 {
		return 0
	}
	switch data[0] {
	case TokenError, TokenInfo, TokenEnvChange, TokenLoginAck, 0xA9: // USHORT length-prefixed (ORDER = 0xA9)
		if len(data) < 3 {
			return 0
		}
		n := 3 + int(binary.LittleEndian.Uint16(data[1:3]))
		if n > len(data) {
			return 0
		}
		return n
	case 0x79: // RETURNSTATUS: token + int32
		if len(data) < 5 {
			return 0
		}
		return 5
	case TokenDone, TokenDoneProc, TokenDoneInProc: // token + status(2) + curcmd(2) + rowcount(8)
		if len(data) < 13 {
			return len(data)
		}
		return 13
	default:
		return 0
	}
}

// ParseErrorTokenMessage extracts the human-readable message from an ERROR
// token (0xAA). Returns an empty string if the token is malformed.
func ParseErrorTokenMessage(data []byte) string {
	// token(1) + length(2) + number(4) + state(1) + class(1) + msg US_VARCHAR
	if len(data) < 11 || data[0] != TokenError {
		return ""
	}
	off := 1 + 2 + 4 + 1 + 1 // past number/state/class
	if off+2 > len(data) {
		return ""
	}
	msgChars := int(binary.LittleEndian.Uint16(data[off:]))
	off += 2
	if off+msgChars*2 > len(data) {
		return ""
	}
	return decodeUTF16LESlice(data[off : off+msgChars*2])
}

func decodeUTF16LESlice(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	u16 := make([]uint16, len(data)/2)
	for i := range u16 {
		u16[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
	}
	return string(utf16.Decode(u16))
}

// isNTextType reports whether the TDS type stores UTF-16LE text (NVARCHAR/NCHAR).
func isNTextType(typeID byte) bool {
	return typeID == 0xE7 || typeID == 0xEF
}

func isFixedLenType(typeID byte) bool {
	switch typeID {
	case 0x30, 0x32, 0x34, 0x38, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x7A, 0x7F:
		return true // INT1, BIT, INT2, INT4, DATETIME4, FLT4, MONEY4, DATETIME, FLT8, MONEY, INT8
	}
	return false
}

func fixedTypeLen(typeID byte) int {
	switch typeID {
	case 0x30, 0x32: // TINYINT, BIT
		return 1
	case 0x34: // SMALLINT
		return 2
	case 0x38, 0x3B: // INT, REAL
		return 4
	case 0x3E, 0x7F: // FLOAT, BIGINT
		return 8
	case 0x3A: // SMALLDATETIME
		return 4
	case 0x3D: // DATETIME
		return 8
	case 0x3C: // SMALLMONEY
		return 4
	case 0x7A: // MONEY
		return 8
	}
	return 0
}
