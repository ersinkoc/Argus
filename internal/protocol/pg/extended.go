package pg

import (
	"encoding/binary"
	"fmt"
)

// ParseMsg represents a parsed Parse message (frontend → backend).
// Parse: 'P' + len + stmt_name\0 + query\0 + num_params(int16) + param_oids...
type ParseMsg struct {
	StatementName string
	Query         string
	ParamOIDs     []int32
}

// DecodeParse extracts fields from a Parse message payload.
func DecodeParse(payload []byte) (*ParseMsg, error) {
	msg := &ParseMsg{}
	i := 0

	// Statement name (null-terminated)
	nameEnd := i
	for nameEnd < len(payload) && payload[nameEnd] != 0 {
		nameEnd++
	}
	if nameEnd >= len(payload) {
		return nil, fmt.Errorf("parse: missing statement name terminator")
	}
	msg.StatementName = string(payload[i:nameEnd])
	i = nameEnd + 1

	// Query (null-terminated)
	queryEnd := i
	for queryEnd < len(payload) && payload[queryEnd] != 0 {
		queryEnd++
	}
	if queryEnd >= len(payload) {
		return nil, fmt.Errorf("parse: missing query terminator")
	}
	msg.Query = string(payload[i:queryEnd])
	i = queryEnd + 1

	// Number of parameter OIDs
	if i+2 > len(payload) {
		return msg, nil // no params specified is valid
	}
	numParams := int(binary.BigEndian.Uint16(payload[i:]))
	i += 2

	// Parameter OIDs
	for j := 0; j < numParams && i+4 <= len(payload); j++ {
		oid := int32(binary.BigEndian.Uint32(payload[i:]))
		msg.ParamOIDs = append(msg.ParamOIDs, oid)
		i += 4
	}

	return msg, nil
}

// BindMsg represents a parsed Bind message (frontend → backend).
// Bind: 'B' + len + portal\0 + stmt\0 + num_formats(int16) + formats...
//       + num_params(int16) + param_values... + num_result_formats(int16) + result_formats...
type BindMsg struct {
	Portal        string
	StatementName string
}

// DecodeBind extracts the portal and statement names from a Bind message.
func DecodeBind(payload []byte) (*BindMsg, error) {
	msg := &BindMsg{}
	i := 0

	// Portal name
	end := i
	for end < len(payload) && payload[end] != 0 {
		end++
	}
	if end >= len(payload) {
		return nil, fmt.Errorf("bind: missing portal name terminator")
	}
	msg.Portal = string(payload[i:end])
	i = end + 1

	// Statement name
	end = i
	for end < len(payload) && payload[end] != 0 {
		end++
	}
	if end >= len(payload) {
		return nil, fmt.Errorf("bind: missing statement name terminator")
	}
	msg.StatementName = string(payload[i:end])

	return msg, nil
}

// IsExtendedQueryMsg returns true if the message type is part of the Extended Query protocol.
func IsExtendedQueryMsg(msgType byte) bool {
	switch msgType {
	case MsgParse, MsgBind, MsgFlush:
		return true
	case 'D': // Describe (frontend) — same byte as DataRow (backend)
		return true
	case 'E': // Execute (frontend) — same byte as ErrorResponse (backend)
		return true
	case 'S': // Sync (frontend) — same byte as ParameterStatus (backend)
		return true
	case 'C': // Close (frontend) — same byte as CommandComplete (backend)
		return true
	}
	return false
}

// IsExtendedQueryBackendMsg returns true if the message type is an Extended Query backend response.
func IsExtendedQueryBackendMsg(msgType byte) bool {
	switch msgType {
	case MsgParseComplete, MsgBindComplete, MsgCloseComplete,
		MsgParameterDesc, MsgPortalSuspended, MsgNoData:
		return true
	}
	return false
}
