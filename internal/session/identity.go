package session

import "net"

// Info holds session identity information resolved during authentication.
type Info struct {
	Username   string
	Database   string
	ClientIP   net.IP
	AuthMethod string
	Parameters map[string]string // client-sent parameters (application_name, etc.)
}
