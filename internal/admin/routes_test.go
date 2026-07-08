package admin

import (
	"net/http"
	"testing"
)

func TestRouteInventoryModesAndGatewayPaths(t *testing.T) {
	srv := NewServer(nil, ":0")
	srv.SetRouteModes(true, true)
	srv.SetGateway(fakeGatewayHandler{}, nil)

	routes := srv.RouteInventory()
	if len(routes) == 0 {
		t.Fatal("RouteInventory returned no routes")
	}

	seen := map[string]RouteSpec{}
	for _, route := range routes {
		seen[route.Path] = route
	}
	if _, ok := seen["/healthz"]; !ok {
		t.Fatal("expected /healthz route")
	}
	if got, ok := seen["/api/gateway/query"]; !ok || !got.UsesGatewayAPIKey {
		t.Fatalf("expected /api/gateway/query to require gateway API key, got %+v", got)
	}
	if got, ok := seen["/api/stats"]; !ok || !got.RequiresAdminAuth {
		t.Fatalf("expected /api/stats to require admin auth, got %+v", got)
	}

	public := srv.GatewayPublicPaths()
	if len(public) != 5 {
		t.Fatalf("GatewayPublicPaths len = %d, want 5", len(public))
	}
}

func TestRouteInventoryWithoutAdminRoutes(t *testing.T) {
	srv := NewServer(nil, ":0")
	srv.SetRouteModes(false, true)
	srv.SetGateway(fakeGatewayHandler{}, nil)

	for _, route := range srv.RouteInventory() {
		if route.Group == "admin" || route.Group == "gateway" {
			t.Fatalf("unexpected route when admin disabled: %+v", route)
		}
	}
	if got := len(srv.GatewayPublicPaths()); got != 0 {
		t.Fatalf("GatewayPublicPaths len = %d, want 0", got)
	}
}

type fakeGatewayHandler struct{}

func (fakeGatewayHandler) HandleQuery(w http.ResponseWriter, r *http.Request)       {}
func (fakeGatewayHandler) HandleApprove(w http.ResponseWriter, r *http.Request)     {}
func (fakeGatewayHandler) HandleAllowlist(w http.ResponseWriter, r *http.Request)   {}
func (fakeGatewayHandler) HandleQueryStatus(w http.ResponseWriter, r *http.Request) {}
func (fakeGatewayHandler) HandleDryRun(w http.ResponseWriter, r *http.Request)      {}
