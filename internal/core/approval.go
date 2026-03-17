package core

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ApprovalStatus represents the state of an approval request.
type ApprovalStatus int

const (
	ApprovalPending  ApprovalStatus = iota
	ApprovalApproved
	ApprovalDenied
	ApprovalExpired
)

// ApprovalRequest represents a pending approval for a high-risk command.
type ApprovalRequest struct {
	ID          string         `json:"id"`
	SessionID   string         `json:"session_id"`
	Username    string         `json:"username"`
	Database    string         `json:"database"`
	SQL         string         `json:"sql"`
	RiskLevel   string         `json:"risk_level"`
	PolicyName  string         `json:"policy_name"`
	Status      ApprovalStatus `json:"status"`
	RequestedAt time.Time      `json:"requested_at"`
	ResolvedAt  time.Time      `json:"resolved_at,omitempty"`
	ResolvedBy  string         `json:"resolved_by,omitempty"`
	Reason      string         `json:"reason,omitempty"`

	doneCh chan ApprovalStatus
}

// ApprovalManager handles approval workflows for high-risk commands.
type ApprovalManager struct {
	mu       sync.RWMutex
	pending  map[string]*ApprovalRequest
	timeout  time.Duration
	onNotify func(*ApprovalRequest) // callback to notify admins
}

// NewApprovalManager creates an approval manager.
func NewApprovalManager(timeout time.Duration) *ApprovalManager {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &ApprovalManager{
		pending: make(map[string]*ApprovalRequest),
		timeout: timeout,
	}
}

// OnNotify sets a callback for new approval requests (e.g., WebSocket broadcast).
func (am *ApprovalManager) OnNotify(fn func(*ApprovalRequest)) {
	am.onNotify = fn
}

// RequestApproval creates a pending approval and blocks until approved, denied, or timeout.
func (am *ApprovalManager) RequestApproval(ctx context.Context, req *ApprovalRequest) (ApprovalStatus, error) {
	req.Status = ApprovalPending
	req.RequestedAt = time.Now()
	req.doneCh = make(chan ApprovalStatus, 1)

	am.mu.Lock()
	am.pending[req.ID] = req
	am.mu.Unlock()

	// Notify admins
	if am.onNotify != nil {
		am.onNotify(req)
	}

	// Wait for resolution
	timeoutCh := time.After(am.timeout)
	select {
	case status := <-req.doneCh:
		return status, nil
	case <-timeoutCh:
		am.mu.Lock()
		req.Status = ApprovalExpired
		delete(am.pending, req.ID)
		am.mu.Unlock()
		return ApprovalExpired, fmt.Errorf("approval request timed out after %v", am.timeout)
	case <-ctx.Done():
		am.mu.Lock()
		delete(am.pending, req.ID)
		am.mu.Unlock()
		return ApprovalDenied, ctx.Err()
	}
}

// Approve approves a pending request.
func (am *ApprovalManager) Approve(id, approver string) error {
	am.mu.Lock()
	req, ok := am.pending[id]
	if !ok {
		am.mu.Unlock()
		return fmt.Errorf("approval request %q not found or already resolved", id)
	}
	req.Status = ApprovalApproved
	req.ResolvedAt = time.Now()
	req.ResolvedBy = approver
	delete(am.pending, id)
	am.mu.Unlock()

	req.doneCh <- ApprovalApproved
	return nil
}

// Deny denies a pending request.
func (am *ApprovalManager) Deny(id, approver, reason string) error {
	am.mu.Lock()
	req, ok := am.pending[id]
	if !ok {
		am.mu.Unlock()
		return fmt.Errorf("approval request %q not found or already resolved", id)
	}
	req.Status = ApprovalDenied
	req.ResolvedAt = time.Now()
	req.ResolvedBy = approver
	req.Reason = reason
	delete(am.pending, id)
	am.mu.Unlock()

	req.doneCh <- ApprovalDenied
	return nil
}

// PendingRequests returns all pending approval requests (as []any for interface compat).
func (am *ApprovalManager) PendingRequests() []any {
	am.mu.RLock()
	defer am.mu.RUnlock()

	result := make([]any, 0, len(am.pending))
	for _, req := range am.pending {
		result = append(result, req)
	}
	return result
}

// Count returns the number of pending requests.
func (am *ApprovalManager) Count() int {
	am.mu.RLock()
	defer am.mu.RUnlock()
	return len(am.pending)
}
