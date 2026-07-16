package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryStore is a concurrency-safe in-memory todo store.
type MemoryStore struct {
	mu    sync.RWMutex
	todos map[string]*Todo
}

// NewMemoryStore creates and returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		todos: make(map[string]*Todo),
	}
}

// List returns todos ordered by creation time (oldest first), with
// optional cursor-based pagination.
func (s *MemoryStore) List(p ListParams) (*ListResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Collect and sort by created_at ASC.
	all := make([]*Todo, 0, len(s.todos))
	for _, t := range s.todos {
		all = append(all, t)
	}
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			if all[j].CreatedAt.Before(all[i].CreatedAt) {
				all[i], all[j] = all[j], all[i]
			}
		}
	}

	// Apply cursor filter (exclusive).
	var after time.Time
	if p.Cursor != "" {
		var err error
		after, err = time.Parse(time.RFC3339Nano, p.Cursor)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor: %w", err)
		}
	}

	filtered := make([]*Todo, 0, len(all))
	for _, t := range all {
		if !t.CreatedAt.After(after) {
			continue
		}
		if p.Completed != nil && t.Completed != *p.Completed {
			continue
		}
		filtered = append(filtered, t)
	}

	// Apply limit (fetch one extra to detect hasMore).
	limit := p.Limit
	if limit == 0 {
		limit = len(filtered)
	}

	end := limit
	hasMore := false
	if end < len(filtered) {
		end = limit
		hasMore = true
	}
	if end > len(filtered) {
		end = len(filtered)
	}

	items := filtered[:end]
	nextCursor := ""
	if hasMore && len(items) > 0 {
		nextCursor = items[len(items)-1].CreatedAt.Format(time.RFC3339Nano)
	}
	return &ListResult{Items: items, NextCursor: nextCursor}, nil
}

// Get returns a single todo by ID.
func (s *MemoryStore) Get(id string) (*Todo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	t, ok := s.todos[id]
	if !ok {
		return nil, fmt.Errorf("todo %q not found", id)
	}
	return t, nil
}

// Create adds a new todo with the given title.
func (s *MemoryStore) Create(title string) (*Todo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	t := &Todo{
		ID:        uuid.NewString(),
		Title:     title,
		Completed: false,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.todos[t.ID] = t
	return t, nil
}

// Update modifies an existing todo. Only non-nil fields are applied.
func (s *MemoryStore) Update(id string, req UpdateTodoRequest) (*Todo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.todos[id]
	if !ok {
		return nil, fmt.Errorf("todo %q not found", id)
	}

	if req.Title != nil {
		t.Title = *req.Title
	}
	if req.Completed != nil {
		t.Completed = *req.Completed
	}
	t.UpdatedAt = time.Now().UTC()
	return t, nil
}

// Delete removes a todo by ID.
func (s *MemoryStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.todos[id]; !ok {
		return fmt.Errorf("todo %q not found", id)
	}
	delete(s.todos, id)
	return nil
}

// DeleteCompleted removes all completed todos and returns the count.
func (s *MemoryStore) DeleteCompleted() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int64
	for id, t := range s.todos {
		if t.Completed {
			delete(s.todos, id)
			count++
		}
	}
	return count, nil
}
