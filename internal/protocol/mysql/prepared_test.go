package mysql

import (
	"encoding/binary"
	"testing"
)

func TestStmtStore(t *testing.T) {
	store := NewStmtStore()

	stmt := &PreparedStatement{ID: 1, SQL: "SELECT * FROM users WHERE id = ?", NumParams: 1, NumCols: 3}
	store.Add(stmt)

	got := store.Get(1)
	if got == nil {
		t.Fatal("should find statement 1")
	}
	if got.SQL != "SELECT * FROM users WHERE id = ?" {
		t.Errorf("SQL = %q", got.SQL)
	}

	if store.Get(999) != nil {
		t.Error("should return nil for unknown ID")
	}

	store.Remove(1)
	if store.Get(1) != nil {
		t.Error("should be removed")
	}
}

func TestHandleExecute(t *testing.T) {
	store := NewStmtStore()
	store.Add(&PreparedStatement{ID: 42, SQL: "SELECT * FROM orders WHERE id = ?", NumParams: 1})

	// Build COM_STMT_EXECUTE payload
	payload := make([]byte, 5)
	payload[0] = ComStmtExecute
	binary.LittleEndian.PutUint32(payload[1:5], 42)

	pkt := &Packet{Payload: payload}
	stmtID, sql := HandleExecute(pkt, store)

	if stmtID != 42 {
		t.Errorf("stmtID = %d, want 42", stmtID)
	}
	if sql != "SELECT * FROM orders WHERE id = ?" {
		t.Errorf("SQL = %q", sql)
	}
}

func TestHandleExecuteUnknown(t *testing.T) {
	store := NewStmtStore()

	payload := make([]byte, 5)
	payload[0] = ComStmtExecute
	binary.LittleEndian.PutUint32(payload[1:5], 999)

	_, sql := HandleExecute(&Packet{Payload: payload}, store)
	if sql != "" {
		t.Errorf("unknown stmt should return empty SQL, got %q", sql)
	}
}

func TestHandleClose(t *testing.T) {
	store := NewStmtStore()
	store.Add(&PreparedStatement{ID: 10, SQL: "SELECT 1"})

	payload := make([]byte, 5)
	payload[0] = ComStmtClose
	binary.LittleEndian.PutUint32(payload[1:5], 10)

	HandleClose(&Packet{Payload: payload}, store)

	if store.Get(10) != nil {
		t.Error("statement should be removed after close")
	}
}
