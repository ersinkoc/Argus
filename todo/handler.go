package main

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
)

// Handlers groups all HTTP handlers for the todo resource.
type Handlers struct {
	store Store
}

// NewHandlers creates handlers backed by the given store.
func NewHandlers(store Store) *Handlers {
	return &Handlers{store: store}
}

// ListTodos  GET /api/todos[?cursor=...&limit=20&completed=true]
func (h *Handlers) ListTodos(c echo.Context) error {
	cursor := c.QueryParam("cursor")
	limit := 20 // default page size
	if l := c.QueryParam("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}

	var completed *bool
	if c := c.QueryParam("completed"); c != "" {
		switch c {
		case "true":
			completed = boolPtr(true)
		case "false":
			completed = boolPtr(false)
		default:
			return apiError(ErrorValidation, http.StatusBadRequest, "completed must be \"true\" or \"false\"")
		}
	}

	result, err := h.store.List(ListParams{Cursor: cursor, Limit: limit, Completed: completed})
	if err != nil {
		return apiError(ErrorInternal, http.StatusInternalServerError, "failed to list todos")
	}

	hasMore := result.NextCursor != ""
	return c.JSON(http.StatusOK, map[string]any{
		"data":       result.Items,
		"nextCursor": result.NextCursor,
		"hasMore":    hasMore,
	})
}

// CreateTodo  POST /api/todos
func (h *Handlers) CreateTodo(c echo.Context) error {
	var req CreateTodoRequest
	if err := c.Bind(&req); err != nil {
		return apiError(ErrorValidation, http.StatusBadRequest, "invalid request body")
	}
	if req.Title == "" {
		return apiError(ErrorValidation, http.StatusBadRequest, "title is required")
	}

	todo, err := h.store.Create(req.Title)
	if err != nil {
		return apiError(ErrorInternal, http.StatusInternalServerError, "failed to create todo")
	}
	return c.JSON(http.StatusCreated, todo)
}

// GetTodo  GET /api/todos/:id
func (h *Handlers) GetTodo(c echo.Context) error {
	id := c.Param("id")
	todo, err := h.store.Get(id)
	if err != nil {
		return apiError(ErrorNotFound, http.StatusNotFound, err.Error())
	}
	return c.JSON(http.StatusOK, todo)
}

// UpdateTodo  PUT /api/todos/:id
func (h *Handlers) UpdateTodo(c echo.Context) error {
	id := c.Param("id")

	var req UpdateTodoRequest
	if err := c.Bind(&req); err != nil {
		return apiError(ErrorValidation, http.StatusBadRequest, "invalid request body")
	}
	if req.Title != nil && *req.Title == "" {
		return apiError(ErrorValidation, http.StatusBadRequest, "title cannot be empty")
	}

	todo, err := h.store.Update(id, req)
	if err != nil {
		return apiError(ErrorNotFound, http.StatusNotFound, err.Error())
	}
	return c.JSON(http.StatusOK, todo)
}

// DeleteTodo  DELETE /api/todos/:id
func (h *Handlers) DeleteTodo(c echo.Context) error {
	id := c.Param("id")
	if err := h.store.Delete(id); err != nil {
		return apiError(ErrorNotFound, http.StatusNotFound, err.Error())
	}
	return c.NoContent(http.StatusNoContent)
}

// DeleteCompletedTodos  DELETE /api/todos
func (h *Handlers) DeleteCompletedTodos(c echo.Context) error {
	n, err := h.store.DeleteCompleted()
	if err != nil {
		return apiError(ErrorInternal, http.StatusInternalServerError, "failed to delete completed todos")
	}
	return c.JSON(http.StatusOK, map[string]any{
		"deleted": n,
	})
}

// pinger is an optional interface stores can implement to report liveness.
type pinger interface {
	Ping() error
}

// HealthCheck  GET /health
func (h *Handlers) HealthCheck(c echo.Context) error {
	if p, ok := h.store.(pinger); ok {
		if err := p.Ping(); err != nil {
			return c.JSON(http.StatusServiceUnavailable, map[string]any{
				"status": "unhealthy",
				"error":  err.Error(),
			})
		}
	}
	return c.JSON(http.StatusOK, map[string]any{"status": "ok"})
}
