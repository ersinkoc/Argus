package core

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestApprovalApprove(t *testing.T) {
	am := NewApprovalManager(5 * time.Second)

	req := &ApprovalRequest{
		ID:        "req-1",
		SessionID: "sess-1",
		Username:  "dev_john",
		SQL:       "DROP TABLE users",
		RiskLevel: "high",
	}

	// Approve in background
	go func() {
		time.Sleep(50 * time.Millisecond)
		am.Approve("req-1", "admin")
	}()

	status, err := am.RequestApproval(context.Background(), req)
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if status != ApprovalApproved {
		t.Errorf("status = %d, want Approved", status)
	}
}

func TestApprovalDeny(t *testing.T) {
	am := NewApprovalManager(5 * time.Second)

	req := &ApprovalRequest{
		ID:       "req-2",
		Username: "dev_john",
		SQL:      "DROP TABLE users",
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		am.Deny("req-2", "admin", "not allowed")
	}()

	status, err := am.RequestApproval(context.Background(), req)
	if err != nil {
		t.Fatalf("RequestApproval: %v", err)
	}
	if status != ApprovalDenied {
		t.Errorf("status = %d, want Denied", status)
	}
}

func TestApprovalTimeout(t *testing.T) {
	am := NewApprovalManager(100 * time.Millisecond)

	req := &ApprovalRequest{
		ID:       "req-3",
		Username: "dev_john",
		SQL:      "DROP TABLE users",
	}

	status, err := am.RequestApproval(context.Background(), req)
	if err == nil {
		t.Error("should return timeout error")
	}
	if status != ApprovalExpired {
		t.Errorf("status = %d, want Expired", status)
	}
}

func TestApprovalContextCancel(t *testing.T) {
	am := NewApprovalManager(5 * time.Second)

	req := &ApprovalRequest{
		ID:       "req-4",
		Username: "dev_john",
		SQL:      "DROP TABLE users",
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	status, _ := am.RequestApproval(ctx, req)
	if status != ApprovalDenied {
		t.Errorf("status = %d, want Denied (context cancelled)", status)
	}
}

func TestApprovalPendingRequests(t *testing.T) {
	am := NewApprovalManager(5 * time.Second)

	// Create pending requests in background
	for i := 0; i < 3; i++ {
		req := &ApprovalRequest{
			ID:       fmt.Sprintf("req-%d", i),
			Username: "dev_john",
			SQL:      "DROP TABLE users",
		}
		go am.RequestApproval(context.Background(), req)
	}

	time.Sleep(50 * time.Millisecond) // let goroutines register

	pending := am.PendingRequests()
	if len(pending) != 3 {
		t.Errorf("pending = %d, want 3", len(pending))
	}

	// Approve all
	for _, p := range pending {
		req := p.(*ApprovalRequest)
		am.Approve(req.ID, "admin")
	}

	if am.Count() != 0 {
		t.Errorf("after approval, pending = %d, want 0", am.Count())
	}
}

func TestApprovalNotify(t *testing.T) {
	am := NewApprovalManager(5 * time.Second)
	notified := false
	am.OnNotify(func(req *ApprovalRequest) {
		notified = true
	})

	req := &ApprovalRequest{ID: "req-5", Username: "dev"}

	go func() {
		time.Sleep(20 * time.Millisecond)
		am.Approve("req-5", "admin")
	}()

	am.RequestApproval(context.Background(), req)

	if !notified {
		t.Error("OnNotify should have been called")
	}
}
