package mysql

import (
	"encoding/binary"
	"fmt"
	"net"
)

// MySQL Prepared Statement command bytes
const (
	ComStmtPrepare  byte = 0x16
	ComStmtExecute  byte = 0x17
	ComStmtClose    byte = 0x19
	ComStmtReset    byte = 0x1A
)

// PreparedStatement tracks a server-side prepared statement.
type PreparedStatement struct {
	ID        uint32
	SQL       string
	NumParams int
	NumCols   int
}

// StmtStore tracks prepared statements per connection.
type StmtStore struct {
	stmts map[uint32]*PreparedStatement
}

// NewStmtStore creates a statement store.
func NewStmtStore() *StmtStore {
	return &StmtStore{stmts: make(map[uint32]*PreparedStatement)}
}

// Add registers a prepared statement.
func (s *StmtStore) Add(stmt *PreparedStatement) {
	s.stmts[stmt.ID] = stmt
}

// Get returns a prepared statement by ID.
func (s *StmtStore) Get(id uint32) *PreparedStatement {
	return s.stmts[id]
}

// Remove deletes a prepared statement.
func (s *StmtStore) Remove(id uint32) {
	delete(s.stmts, id)
}

// HandlePrepare processes COM_STMT_PREPARE: forwards to backend and tracks the response.
func HandlePrepare(client, backend net.Conn, pkt *Packet, store *StmtStore) error {
	// Forward COM_STMT_PREPARE to backend
	if err := WritePacket(backend, pkt); err != nil {
		return fmt.Errorf("forwarding COM_STMT_PREPARE: %w", err)
	}

	// Read response from backend
	resp, err := ReadPacket(backend)
	if err != nil {
		return fmt.Errorf("reading prepare response: %w", err)
	}

	// Forward to client
	if err := WritePacket(client, resp); err != nil {
		return fmt.Errorf("forwarding prepare response: %w", err)
	}

	// Parse OK response: 0x00 + stmt_id(4) + num_cols(2) + num_params(2) + filler(1) + warnings(2)
	if len(resp.Payload) > 0 && resp.Payload[0] == 0x00 && len(resp.Payload) >= 12 {
		stmtID := binary.LittleEndian.Uint32(resp.Payload[1:5])
		numCols := int(binary.LittleEndian.Uint16(resp.Payload[5:7]))
		numParams := int(binary.LittleEndian.Uint16(resp.Payload[7:9]))

		sql := ""
		if len(pkt.Payload) > 1 {
			sql = string(pkt.Payload[1:])
		}

		store.Add(&PreparedStatement{
			ID:        stmtID,
			SQL:       sql,
			NumParams: numParams,
			NumCols:   numCols,
		})

		// Forward parameter definitions if any
		if numParams > 0 {
			for i := 0; i < numParams; i++ {
				paramPkt, err := ReadPacket(backend)
				if err != nil {
					return err
				}
				WritePacket(client, paramPkt)
			}
			// EOF
			eofPkt, err := ReadPacket(backend)
			if err != nil {
				return err
			}
			WritePacket(client, eofPkt)
		}

		// Forward column definitions if any
		if numCols > 0 {
			for i := 0; i < numCols; i++ {
				colPkt, err := ReadPacket(backend)
				if err != nil {
					return err
				}
				WritePacket(client, colPkt)
			}
			// EOF
			eofPkt, err := ReadPacket(backend)
			if err != nil {
				return err
			}
			WritePacket(client, eofPkt)
		}
	}

	return nil
}

// HandleExecute processes COM_STMT_EXECUTE: extracts stmt ID, looks up SQL for inspection.
func HandleExecute(pkt *Packet, store *StmtStore) (stmtID uint32, sql string) {
	if len(pkt.Payload) < 5 {
		return 0, ""
	}
	stmtID = binary.LittleEndian.Uint32(pkt.Payload[1:5])
	stmt := store.Get(stmtID)
	if stmt != nil {
		sql = stmt.SQL
	}
	return stmtID, sql
}

// HandleClose processes COM_STMT_CLOSE: removes the statement from store.
func HandleClose(pkt *Packet, store *StmtStore) {
	if len(pkt.Payload) < 5 {
		return
	}
	stmtID := binary.LittleEndian.Uint32(pkt.Payload[1:5])
	store.Remove(stmtID)
}
