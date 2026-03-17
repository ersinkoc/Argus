package core

import (
	"github.com/ersinkoc/argus/internal/protocol"
	"github.com/ersinkoc/argus/internal/protocol/mysql"
	"github.com/ersinkoc/argus/internal/protocol/pg"
)

// Router selects the appropriate protocol handler.
type Router struct {
	handlers map[string]protocol.Handler
}

// NewRouter creates a new router with registered protocol handlers.
func NewRouter() *Router {
	r := &Router{
		handlers: make(map[string]protocol.Handler),
	}
	// Register built-in handlers
	r.Register(pg.New())
	r.Register(mysql.New())
	return r
}

// Register adds a protocol handler.
func (r *Router) Register(h protocol.Handler) {
	r.handlers[h.Name()] = h
}

// GetHandler returns the handler for a named protocol.
func (r *Router) GetHandler(protocol string) protocol.Handler {
	return r.handlers[protocol]
}

// DetectHandler tries to identify the protocol from initial bytes.
func (r *Router) DetectHandler(peek []byte) protocol.Handler {
	for _, h := range r.handlers {
		if h.DetectProtocol(peek) {
			return h
		}
	}
	return nil
}
