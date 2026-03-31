package core

import (
	"context"
	"testing"
	"time"
)

func TestApprovalGet(t *testing.T) {
	am := NewApprovalManager(5 * time.Minute)

	// Get non-existent
	if am.Get("nonexistent") != nil {
		t.Error("expected nil for non-existent ID")
	}

	// Submit and get
	id, err := am.SubmitForApproval(&ApprovalRequest{
		Username: "alice", Database: "db", SQL: "SELECT 1",
		Source: "gateway",
	})
	if err != nil {
		t.Fatal(err)
	}

	req := am.Get(id)
	if req == nil {
		t.Fatal("expected non-nil for submitted request")
	}
	if req.Username != "alice" {
		t.Errorf("username = %q, want alice", req.Username)
	}
	if req.Source != "gateway" {
		t.Errorf("source = %q, want gateway", req.Source)
	}

	// Approve and verify it's gone
	am.Approve(id, "admin")
	if am.Get(id) != nil {
		t.Error("approved request should be removed from pending")
	}
}

func TestSubmitForApprovalDuplicate(t *testing.T) {
	am := NewApprovalManager(5 * time.Minute)

	req := &ApprovalRequest{ID: "fixed-id", Username: "alice", SQL: "SELECT 1"}
	_, err := am.SubmitForApproval(req)
	if err != nil {
		t.Fatal(err)
	}

	// Duplicate ID should fail
	req2 := &ApprovalRequest{ID: "fixed-id", Username: "bob", SQL: "SELECT 2"}
	_, err = am.SubmitForApproval(req2)
	if err == nil {
		t.Error("expected error for duplicate ID")
	}
}

func TestSubmitForApprovalAutoID(t *testing.T) {
	am := NewApprovalManager(5 * time.Minute)

	req := &ApprovalRequest{Username: "alice", SQL: "SELECT 1"}
	id, err := am.SubmitForApproval(req)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Error("auto-generated ID should not be empty")
	}
	if len(id) != 16 { // 8 bytes hex = 16 chars
		t.Errorf("auto-generated ID length = %d, want 16", len(id))
	}
}

func TestWaitForResolution(t *testing.T) {
	am := NewApprovalManager(5 * time.Minute)

	id, _ := am.SubmitForApproval(&ApprovalRequest{
		Username: "alice", SQL: "SELECT 1",
	})

	// Approve in background
	go func() {
		time.Sleep(50 * time.Millisecond)
		am.Approve(id, "admin")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	status, err := am.WaitForResolution(ctx, id)
	if err != nil {
		t.Fatalf("WaitForResolution error: %v", err)
	}
	if status != ApprovalApproved {
		t.Errorf("status = %v, want approved", status)
	}
}

func TestWaitForResolutionNotFound(t *testing.T) {
	am := NewApprovalManager(5 * time.Minute)

	_, err := am.WaitForResolution(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for non-existent approval")
	}
}

func TestWaitForResolutionContextCancel(t *testing.T) {
	am := NewApprovalManager(5 * time.Minute)

	id, _ := am.SubmitForApproval(&ApprovalRequest{
		Username: "alice", SQL: "SELECT 1",
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	status, err := am.WaitForResolution(ctx, id)
	if err == nil {
		t.Error("expected error on cancelled context")
	}
	if status != ApprovalDenied {
		t.Errorf("status = %v, want denied", status)
	}
}
