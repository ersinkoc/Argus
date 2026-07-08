package admin

// RouteSpec describes a registered admin/metrics/gateway HTTP route.
type RouteSpec struct {
	Path              string
	Methods           []string
	Group             string
	RequiresAdminAuth bool
	UsesGatewayAPIKey bool
}

// RouteInventory returns the routes exposed by this server configuration.
func (s *Server) RouteInventory() []RouteSpec {
	var routes []RouteSpec
	if s.enableMetricRoutes {
		routes = append(routes,
			RouteSpec{Path: "/healthz", Methods: []string{"GET"}, Group: "metrics"},
			RouteSpec{Path: "/metrics", Methods: []string{"GET"}, Group: "metrics"},
			RouteSpec{Path: "/ready", Methods: []string{"GET"}, Group: "metrics"},
			RouteSpec{Path: "/readyz", Methods: []string{"GET"}, Group: "metrics"},
			RouteSpec{Path: "/livez", Methods: []string{"GET"}, Group: "metrics"},
		)
	}
	if s.enableAdminRoutes {
		routes = append(routes,
			RouteSpec{Path: "/api/sessions", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/sessions/kill", Methods: []string{"POST", "DELETE"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/policies/reload", Methods: []string{"POST"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/stats", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/events/ws", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/approvals", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/approvals/approve", Methods: []string{"POST"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/approvals/deny", Methods: []string{"POST"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/audit/search", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/audit/replay", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/audit/fingerprints", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/policies/dryrun", Methods: []string{"POST"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/config/export", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/audit/compact", Methods: []string{"POST"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/audit/verify", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/policies/validate", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/audit/export", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/pool/health", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/health/deep", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/dashboard", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/classify", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/plugins", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/ui", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/ui/test", Methods: []string{"GET"}, Group: "admin", RequiresAdminAuth: true},
			RouteSpec{Path: "/api/test/run", Methods: []string{"POST"}, Group: "admin", RequiresAdminAuth: true},
		)
	}
	if s.enableAdminRoutes && s.gatewayHandler != nil {
		routes = append(routes,
			RouteSpec{Path: "/api/gateway/query", Methods: []string{"POST"}, Group: "gateway", UsesGatewayAPIKey: true},
			RouteSpec{Path: "/api/gateway/approve", Methods: []string{"POST"}, Group: "gateway", UsesGatewayAPIKey: true},
			RouteSpec{Path: "/api/gateway/allowlist", Methods: []string{"GET", "DELETE"}, Group: "gateway", UsesGatewayAPIKey: true},
			RouteSpec{Path: "/api/gateway/status", Methods: []string{"GET"}, Group: "gateway", UsesGatewayAPIKey: true},
			RouteSpec{Path: "/api/gateway/dryrun", Methods: []string{"POST"}, Group: "gateway", UsesGatewayAPIKey: true},
		)
	}
	return routes
}

// GatewayPublicPaths returns gateway routes that must bypass admin bearer auth.
func (s *Server) GatewayPublicPaths() []string {
	routes := s.RouteInventory()
	paths := make([]string, 0, len(routes))
	for _, route := range routes {
		if route.UsesGatewayAPIKey {
			paths = append(paths, route.Path)
		}
	}
	return paths
}
