package admin

import "net/http"

// CORS wraps an http.Handler to add CORS headers.
// In development, admin UI runs on a different port (5173) and needs CORS.
// In production, both UI and API are served from the same origin.
type CORS struct {
	next       http.Handler
	allowAll   bool
	allowOrigins []string
}

// NewCORS creates a CORS middleware.
func NewCORS(next http.Handler, allowAll bool, allowOrigins ...string) *CORS {
	return &CORS{
		next:         next,
		allowAll:     allowAll,
		allowOrigins: allowOrigins,
	}
}

func (c *CORS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")

	// Determine if we should allow this origin
	if c.allowAll {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else if origin != "" {
		for _, allowed := range c.allowOrigins {
			if allowed == origin || allowed == "*" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}
	}

	// If we set an origin, add the rest of the CORS headers
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400")
	}

	// Handle preflight
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	c.next.ServeHTTP(w, r)
}
