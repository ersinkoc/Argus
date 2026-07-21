package session

import "net"

// Info holds session identity information resolved during authentication.
type Info struct {
	Username   string
	Database   string
	ClientIP   net.IP
	AuthMethod string
	Parameters map[string]string // client-sent parameters (application_name, etc.)
	// Roles are supplied by the identity resolver (proxy-auth mode). In that mode the wire
	// username is an opaque handle, so per-user policy roles cannot be derived from it and must
	// be carried here from the resolve response. Empty for passthrough/static sessions.
	Roles []string
}
