package mongodb

import "testing"

func TestOpCodeNameAll(t *testing.T) {
	tests := []struct {
		code int32
		want string
	}{
		{OpReply, "OP_REPLY"},
		{OpUpdate, "OP_UPDATE"},
		{OpInsert, "OP_INSERT"},
		{OpQuery, "OP_QUERY"},
		{OpGetMore, "OP_GET_MORE"},
		{OpDelete, "OP_DELETE"},
		{OpKillCursors, "OP_KILL_CURSORS"},
		{OpCompressed, "OP_COMPRESSED"},
		{OpMsg, "OP_MSG"},
		{9999, "UNKNOWN(9999)"},
	}
	for _, tt := range tests {
		got := OpCodeName(tt.code)
		if got != tt.want {
			t.Errorf("OpCodeName(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

func TestParseOpMsgDocumentSequence(t *testing.T) {
	var payload []byte
	// FlagBits
	payload = append(payload, 0, 0, 0, 0)

	// Section kind=1 (document sequence)
	payload = append(payload, 1)
	// Sequence: 4-byte length + identifier + docs
	seqData := []byte{8, 0, 0, 0, 't', 'e', 's', 't'} // len=8, "test"
	payload = append(payload, seqData...)

	_, sections, err := ParseOpMsg(payload)
	if err != nil {
		t.Fatalf("ParseOpMsg: %v", err)
	}
	if len(sections) != 1 {
		t.Fatalf("sections = %d", len(sections))
	}
	if sections[0].Kind != 1 {
		t.Errorf("kind = %d", sections[0].Kind)
	}
}

func TestParseOpMsgUnknownKind(t *testing.T) {
	payload := []byte{0, 0, 0, 0, 99} // flagBits + unknown kind 99
	_, _, err := ParseOpMsg(payload)
	if err == nil {
		t.Error("unknown kind should fail")
	}
}

func TestClassifyAllCommands(t *testing.T) {
	tests := map[string]string{
		"find": "SELECT", "aggregate": "SELECT", "count": "SELECT", "distinct": "SELECT", "getMore": "SELECT",
		"insert": "INSERT", "insertMany": "INSERT",
		"update": "UPDATE", "updateMany": "UPDATE", "updateOne": "UPDATE", "findAndModify": "UPDATE",
		"delete": "DELETE", "deleteMany": "DELETE", "deleteOne": "DELETE",
		"createCollection": "DDL", "createIndexes": "DDL", "drop": "DDL", "dropDatabase": "DDL",
		"createUser": "DCL", "dropUser": "DCL",
		"ping": "ADMIN", "isMaster": "ADMIN", "hello": "ADMIN", "buildInfo": "ADMIN",
		"randomCmd": "UNKNOWN",
	}
	for cmd, want := range tests {
		got := classifyMongoCommand(cmd).String()
		if got != want {
			t.Errorf("classify(%q) = %q, want %q", cmd, got, want)
		}
	}
}
