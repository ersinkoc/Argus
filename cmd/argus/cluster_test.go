package main

import (
	"testing"

	"github.com/ersinkoc/argus/internal/session"
)

func TestSetupClusterDisabled(t *testing.T) {
	cfg, proxy, _, _, logger := newSetupAdminDeps(t)
	defer logger.Close()

	if manager := setupCluster(cfg, proxy); manager != nil {
		t.Fatal("expected nil manager when cluster is disabled")
	}
}

func TestSetupClusterEnabledMirrorsSessions(t *testing.T) {
	cfg, proxy, _, _, logger := newSetupAdminDeps(t)
	defer logger.Close()
	cfg.Cluster.Enabled = true
	cfg.Cluster.NodeID = "test-node"

	manager := setupCluster(cfg, proxy)
	if manager == nil {
		t.Fatal("expected cluster manager")
	}
	if manager.NodeID() != "test-node" {
		t.Fatalf("NodeID = %q, want test-node", manager.NodeID())
	}
	if nodes := manager.Nodes(); len(nodes) != 1 {
		t.Fatalf("nodes = %d, want 1", len(nodes))
	}

	sess := proxy.SessionManager().Create(&session.Info{Username: "alice", Database: "app"}, nil)
	entries, err := manager.ClusterSessions()
	if err != nil {
		t.Fatalf("ClusterSessions: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != sess.ID || entries[0].NodeID != "test-node" {
		t.Fatalf("entries = %+v, want one entry for session %s on test-node", entries, sess.ID)
	}

	proxy.SessionManager().Remove(sess.ID)
	entries, err = manager.ClusterSessions()
	if err != nil {
		t.Fatalf("ClusterSessions after remove: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries after remove = %d, want 0", len(entries))
	}
}

func TestSetupClusterDefaultNodeID(t *testing.T) {
	cfg, proxy, _, _, logger := newSetupAdminDeps(t)
	defer logger.Close()
	cfg.Cluster.Enabled = true

	manager := setupCluster(cfg, proxy)
	if manager == nil {
		t.Fatal("expected cluster manager")
	}
	if manager.NodeID() == "" {
		t.Fatal("NodeID should default to a non-empty value")
	}
}
