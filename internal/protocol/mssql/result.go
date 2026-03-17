package mssql

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/ersinkoc/argus/internal/masking"
)

// TDSColumnMeta holds parsed column metadata from COLMETADATA token.
type TDSColumnMeta struct {
	Name     string
	TypeID   byte
	MaxLen   int
	Index    int
	IsText   bool // whether the column carries text data we can mask
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

	// For text columns, attempt to find and mask their values
	// This is a simplified approach — full TDS row parsing is very complex
	// because field lengths depend on column type definitions
	result := make([]byte, 0, len(data))
	result = append(result, data[0]) // token byte
	offset := 1

	for _, col := range cols {
		if offset >= len(data) {
			break
		}

		if col.IsText {
			// Variable-length text: 2-byte length prefix + data
			if offset+2 > len(data) {
				result = append(result, data[offset:]...)
				break
			}
			fieldLen := int(binary.LittleEndian.Uint16(data[offset:]))
			result = append(result, data[offset:offset+2]...)
			offset += 2

			if fieldLen == 0xFFFF { // NULL
				continue
			}

			if offset+fieldLen > len(data) {
				result = append(result, data[offset:]...)
				break
			}

			fieldData := data[offset : offset+fieldLen]
			offset += fieldLen

			// Check if this column should be masked
			fieldValue := masking.FieldValue{Data: fieldData}
			row := []masking.FieldValue{fieldValue}
			masked, _ := pipeline.ProcessRow(row)
			if len(masked) > 0 && !masked[0].IsNull {
				// Re-encode with new length
				maskedData := masked[0].Data
				lenBuf := make([]byte, 2)
				binary.LittleEndian.PutUint16(lenBuf, uint16(len(maskedData)))
				// Replace length
				result = result[:len(result)-2]
				result = append(result, lenBuf...)
				result = append(result, maskedData...)
			} else {
				result = append(result, fieldData...)
			}
		} else {
			// Fixed-length: copy as-is
			fieldLen := col.MaxLen
			if offset+fieldLen > len(data) {
				result = append(result, data[offset:]...)
				break
			}
			result = append(result, data[offset:offset+fieldLen]...)
			offset += fieldLen
		}
	}

	// Append any remaining data
	if offset < len(data) {
		result = append(result, data[offset:]...)
	}

	return result
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
