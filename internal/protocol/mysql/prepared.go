package mysql

import "encoding/binary"

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
