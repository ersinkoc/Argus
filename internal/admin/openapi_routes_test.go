package admin

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenAPIDocumentedRoutesMatchInventorySubset(t *testing.T) {
	docPaths, err := documentedOpenAPIPaths(filepath.Join("..", "..", "docs", "openapi.yaml"))
	if err != nil {
		t.Fatalf("documentedOpenAPIPaths: %v", err)
	}

	srv := NewServer(nil, ":0")
	srv.SetRouteModes(true, true)
	srv.SetGateway(fakeGatewayHandler{}, nil)

	inventory := map[string]struct{}{}
	for _, route := range srv.RouteInventory() {
		inventory[route.Path] = struct{}{}
	}

	for _, path := range []string{
		"/healthz", "/livez", "/ready", "/readyz", "/metrics",
		"/api/stats", "/api/sessions", "/api/sessions/kill",
		"/api/policies/reload", "/api/policies/dryrun", "/api/policies/validate",
		"/api/approvals", "/api/approvals/approve", "/api/approvals/deny",
		"/api/audit/search", "/api/audit/export",
		"/api/pool/health", "/api/health/deep", "/api/dashboard", "/api/classify", "/api/plugins",
		"/api/gateway/query", "/api/gateway/approve", "/api/gateway/allowlist", "/api/gateway/status", "/api/gateway/dryrun",
	} {
		if _, ok := docPaths[path]; !ok {
			t.Fatalf("documented OpenAPI paths missing %s", path)
		}
		if _, ok := inventory[path]; !ok {
			t.Fatalf("route inventory missing documented path %s", path)
		}
	}
}

func documentedOpenAPIPaths(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	paths := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	inPaths := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "paths:" {
			inPaths = true
			continue
		}
		if !inPaths {
			continue
		}
		if strings.HasPrefix(line, "components:") {
			break
		}
		if strings.HasPrefix(line, "  /") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			path := strings.TrimSuffix(strings.TrimSpace(line), ":")
			paths[path] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return paths, nil
}
