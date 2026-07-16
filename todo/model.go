package main

import "time"

// Todo represents a single TODO item.
type Todo struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Completed bool      `json:"completed"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateTodoRequest is the payload for creating a new todo.
type CreateTodoRequest struct {
	Title string `json:"title" validate:"required"`
}

// UpdateTodoRequest is the payload for updating an existing todo.
type UpdateTodoRequest struct {
	Title     *string `json:"title,omitempty"`
	Completed *bool   `json:"completed,omitempty"`
}

// boolPtr is a convenience helper for taking the address of a bool literal.
func boolPtr(b bool) *bool { return &b }
