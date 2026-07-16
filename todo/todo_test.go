package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func setupRouter(store Store) (*echo.Echo, error) {
	e := echo.New()
	e.HTTPErrorHandler = customHTTPErrorHandler
	h := NewHandlers(store)

	g := e.Group("/api/todos")
	g.GET("", h.ListTodos)
	g.POST("", h.CreateTodo)
	g.DELETE("", h.DeleteCompletedTodos)
	g.GET("/:id", h.GetTodo)
	g.PUT("/:id", h.UpdateTodo)
	g.DELETE("/:id", h.DeleteTodo)

	return e, nil
}

// listResponse is a helper to unmarshal the paginated list body.
type listResponse struct {
	Data       []*Todo `json:"data"`
	NextCursor string  `json:"nextCursor"`
	HasMore    bool    `json:"hasMore"`
}

func TestMemoryStoreCRUD(t *testing.T) {
	e, _ := setupRouter(NewMemoryStore())

	// CREATE
	body := `{"title":"write tests"}`
	req := httptest.NewRequest(http.MethodPost, "/api/todos", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Create: expected 201, got %d", rec.Code)
	}

	var created Todo
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected a non-empty ID")
	}
	if created.Title != "write tests" {
		t.Fatalf("expected title 'write tests', got %q", created.Title)
	}
	if created.Completed {
		t.Fatal("new todo should not be completed")
	}

	// LIST
	req2 := httptest.NewRequest(http.MethodGet, "/api/todos", nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("List: expected 200, got %d", rec2.Code)
	}
	var list listResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	if len(list.Data) != 1 {
		t.Fatalf("List: expected 1 todo, got %d", len(list.Data))
	}
	if list.NextCursor != "" {
		t.Fatalf("List: expected empty nextCursor for single item, got %q", list.NextCursor)
	}
	if list.HasMore {
		t.Fatal("List: expected hasMore=false for single item")
	}

	// GET
	req3 := httptest.NewRequest(http.MethodGet, "/api/todos/"+created.ID, nil)
	rec3 := httptest.NewRecorder()
	e.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("Get: expected 200, got %d", rec3.Code)
	}

	// UPDATE
	updateBody := `{"completed":true}`
	req4 := httptest.NewRequest(http.MethodPut, "/api/todos/"+created.ID, strings.NewReader(updateBody))
	req4.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec4 := httptest.NewRecorder()
	e.ServeHTTP(rec4, req4)

	if rec4.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d", rec4.Code)
	}
	var updated Todo
	if err := json.Unmarshal(rec4.Body.Bytes(), &updated); err != nil {
		t.Fatalf("unmarshal update response: %v", err)
	}
	if !updated.Completed {
		t.Fatal("todo should be completed after update")
	}

	// DELETE
	req5 := httptest.NewRequest(http.MethodDelete, "/api/todos/"+created.ID, nil)
	rec5 := httptest.NewRecorder()
	e.ServeHTTP(rec5, req5)

	if rec5.Code != http.StatusNoContent {
		t.Fatalf("Delete: expected 204, got %d", rec5.Code)
	}

	// NOT FOUND
	req6 := httptest.NewRequest(http.MethodGet, "/api/todos/"+created.ID, nil)
	rec6 := httptest.NewRecorder()
	e.ServeHTTP(rec6, req6)

	if rec6.Code != http.StatusNotFound {
		t.Fatalf("Get after delete: expected 404, got %d", rec6.Code)
	}
}

func TestMemoryStoreCreateValidation(t *testing.T) {
	e, _ := setupRouter(NewMemoryStore())

	body := `{"title":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/todos", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty title, got %d", rec.Code)
	}
	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if errResp.Error.Code != ErrorValidation {
		t.Fatalf("expected error code %q, got %q", ErrorValidation, errResp.Error.Code)
	}
	if errResp.Error.Message == "" {
		t.Fatal("expected a non-empty error message")
	}
}

func TestMemoryStoreNotFound(t *testing.T) {
	e, _ := setupRouter(NewMemoryStore())

	req := httptest.NewRequest(http.MethodGet, "/api/todos/nonexistent-id", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if errResp.Error.Code != ErrorNotFound {
		t.Fatalf("expected error code %q, got %q", ErrorNotFound, errResp.Error.Code)
	}
	if errResp.Error.Message == "" {
		t.Fatal("expected a non-empty error message")
	}
}

func TestMemoryStoreEmptyTitleUpdate(t *testing.T) {
	e, _ := setupRouter(NewMemoryStore())

	body := `{"title":"valid title"}`
	req := httptest.NewRequest(http.MethodPost, "/api/todos", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	var created Todo
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}

	// Update with empty title
	updateBody := `{"title":""}`
	req2 := httptest.NewRequest(http.MethodPut, "/api/todos/"+created.ID, strings.NewReader(updateBody))
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty title update, got %d", rec2.Code)
	}
	var errResp ErrorResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if errResp.Error.Code != ErrorValidation {
		t.Fatalf("expected error code %q, got %q", ErrorValidation, errResp.Error.Code)
	}
}

// --- Pagination tests ---

func TestMemoryStorePagination(t *testing.T) {
	store := NewMemoryStore()
	e, _ := setupRouter(store)

	// Create 3 todos: their creation timestamps are sequential.
	for _, title := range []string{"first", "second", "third"} {
		_, err := store.Create(title)
		if err != nil {
			t.Fatalf("create %q: %v", title, err)
		}
	}

	// Page 1: limit=2
	req := httptest.NewRequest(http.MethodGet, "/api/todos?limit=2", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Page 1: expected 200, got %d", rec.Code)
	}
	var p1 listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &p1); err != nil {
		t.Fatalf("unmarshal page 1: %v", err)
	}
	if len(p1.Data) != 2 {
		t.Fatalf("Page 1: expected 2 items, got %d", len(p1.Data))
	}
	if p1.Data[0].Title != "first" || p1.Data[1].Title != "second" {
		t.Fatalf("Page 1: expected [first, second], got [%s, %s]", p1.Data[0].Title, p1.Data[1].Title)
	}
	if p1.NextCursor == "" {
		t.Fatal("Page 1: expected non-empty nextCursor")
	}
	if !p1.HasMore {
		t.Fatal("Page 1: expected hasMore=true")
	}

	// Page 2: use nextCursor
	req2 := httptest.NewRequest(http.MethodGet, "/api/todos?cursor="+p1.NextCursor+"&limit=2", nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("Page 2: expected 200, got %d", rec2.Code)
	}
	var p2 listResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &p2); err != nil {
		t.Fatalf("unmarshal page 2: %v", err)
	}
	if len(p2.Data) != 1 {
		t.Fatalf("Page 2: expected 1 item, got %d", len(p2.Data))
	}
	if p2.Data[0].Title != "third" {
		t.Fatalf("Page 2: expected 'third', got %q", p2.Data[0].Title)
	}
	if p2.NextCursor != "" {
		t.Fatalf("Page 2: expected empty nextCursor, got %q", p2.NextCursor)
	}
	if p2.HasMore {
		t.Fatal("Page 2: expected hasMore=false")
	}
}

func TestMemoryStorePaginationEmpty(t *testing.T) {
	e, _ := setupRouter(NewMemoryStore())

	req := httptest.NewRequest(http.MethodGet, "/api/todos?limit=10", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var res listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(res.Data) != 0 {
		t.Fatalf("expected empty data, got %d items", len(res.Data))
	}
	if res.NextCursor != "" {
		t.Fatalf("expected empty nextCursor, got %q", res.NextCursor)
	}
	if res.HasMore {
		t.Fatal("expected hasMore=false")
	}
}

func TestMemoryStorePaginationLimitExact(t *testing.T) {
	store := NewMemoryStore()
	e, _ := setupRouter(store)

	for _, title := range []string{"a", "b"} {
		_, err := store.Create(title)
		if err != nil {
			t.Fatalf("create %q: %v", title, err)
		}
	}

	// limit=2 with exactly 2 items
	req := httptest.NewRequest(http.MethodGet, "/api/todos?limit=2", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	var res listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(res.Data) != 2 {
		t.Fatalf("expected 2 items, got %d", len(res.Data))
	}
	if res.NextCursor != "" {
		t.Fatalf("expected empty nextCursor on exact match, got %q", res.NextCursor)
	}
	if res.HasMore {
		t.Fatal("expected hasMore=false on exact match")
	}
}

// --- Completed filter tests ---

func TestMemoryStoreCompletedFilter(t *testing.T) {
	store := NewMemoryStore()
	e, _ := setupRouter(store)

	_, _ = store.Create("incomplete a")
	t2, _ := store.Create("complete")
	t3, _ := store.Create("incomplete b")
	_, _ = store.Update(t2.ID, UpdateTodoRequest{Completed: boolPtr(true)})
	_, _ = store.Update(t3.ID, UpdateTodoRequest{Completed: boolPtr(false)})

	t.Run("filter completed=true", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/todos?completed=true", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		var res listResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(res.Data) != 1 {
			t.Fatalf("expected 1 completed item, got %d", len(res.Data))
		}
		if res.Data[0].Title != "complete" {
			t.Fatalf("expected 'complete', got %q", res.Data[0].Title)
		}
	})

	t.Run("filter completed=false", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/todos?completed=false", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		var res listResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(res.Data) != 2 {
			t.Fatalf("expected 2 incomplete items, got %d", len(res.Data))
		}
	})

	t.Run("no filter returns all", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/todos", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		var res listResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(res.Data) != 3 {
			t.Fatalf("expected 3 items, got %d", len(res.Data))
		}
	})

	t.Run("invalid completed value", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/todos?completed=yes", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})
}

func TestSQLiteStoreCompletedFilter(t *testing.T) {
	store, err := NewSQLiteStore("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	defer store.Close()

	e, _ := setupRouter(store)

	_, _ = store.Create("task a")
	t2, _ := store.Create("task done")
	_, _ = store.Update(t2.ID, UpdateTodoRequest{Completed: boolPtr(true)})

	t.Run("filter completed=true", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/todos?completed=true", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		var res listResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(res.Data) != 1 || res.Data[0].Title != "task done" {
			t.Fatalf("expected [task done], got %v", titles(res.Data))
		}
	})

	t.Run("filter completed=false", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/todos?completed=false", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		var res listResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(res.Data) != 1 || res.Data[0].Title != "task a" {
			t.Fatalf("expected [task a], got %v", titles(res.Data))
		}
	})
}

// titles extracts titles from a todo slice for readable assertions.
func titles(items []*Todo) []string {
	out := make([]string, len(items))
	for i, t := range items {
		out[i] = t.Title
	}
	return out
}

// --- Batch delete tests ---

func TestMemoryStoreDeleteCompleted(t *testing.T) {
	store := NewMemoryStore()
	e, _ := setupRouter(store)

	// Create 3 todos, complete 2 of them.
	_, _ = store.Create("keep")
	t2, _ := store.Create("delete me")
	t3, _ := store.Create("delete me too")
	_, _ = store.Update(t2.ID, UpdateTodoRequest{Completed: boolPtr(true)})
	_, _ = store.Update(t3.ID, UpdateTodoRequest{Completed: boolPtr(true)})

	req := httptest.NewRequest(http.MethodDelete, "/api/todos", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	deleted, ok := result["deleted"].(float64)
	if !ok || int(deleted) != 2 {
		t.Fatalf("expected deleted=2, got %v", result["deleted"])
	}

	// Verify only the incomplete todo remains.
	req2 := httptest.NewRequest(http.MethodGet, "/api/todos", nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	var list listResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(list.Data) != 1 {
		t.Fatalf("expected 1 remaining todo, got %d", len(list.Data))
	}
	if list.Data[0].Title != "keep" {
		t.Fatalf("expected 'keep', got %q", list.Data[0].Title)
	}
}

func TestMemoryStoreDeleteCompletedNone(t *testing.T) {
	store := NewMemoryStore()
	e, _ := setupRouter(store)

	_, _ = store.Create("only one")

	req := httptest.NewRequest(http.MethodDelete, "/api/todos", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	deleted, ok := result["deleted"].(float64)
	if !ok || int(deleted) != 0 {
		t.Fatalf("expected deleted=0, got %v", result["deleted"])
	}
}

func TestSQLiteStoreDeleteCompleted(t *testing.T) {
	store, err := NewSQLiteStore("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	defer store.Close()

	e, _ := setupRouter(store)

	_, _ = store.Create("keep")
	t2, _ := store.Create("delete me")
	t3, _ := store.Create("delete me too")
	_, _ = store.Update(t2.ID, UpdateTodoRequest{Completed: boolPtr(true)})
	_, _ = store.Update(t3.ID, UpdateTodoRequest{Completed: boolPtr(true)})

	req := httptest.NewRequest(http.MethodDelete, "/api/todos", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	deleted, ok := result["deleted"].(float64)
	if !ok || int(deleted) != 2 {
		t.Fatalf("expected deleted=2, got %v", result["deleted"])
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/todos", nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	var list listResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(list.Data) != 1 {
		t.Fatalf("expected 1 remaining todo, got %d", len(list.Data))
	}
	if list.Data[0].Title != "keep" {
		t.Fatalf("expected 'keep', got %q", list.Data[0].Title)
	}
}

// --- SQLite pagination ---

func TestSQLiteStoreCRUD(t *testing.T) {
	store, err := NewSQLiteStore("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	defer store.Close()

	e, _ := setupRouter(store)

	// CREATE
	body := `{"title":"sqlite todo"}`
	req := httptest.NewRequest(http.MethodPost, "/api/todos", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Create: expected 201, got %d", rec.Code)
	}

	var created Todo
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected a non-empty ID")
	}

	// LIST
	req2 := httptest.NewRequest(http.MethodGet, "/api/todos", nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("List: expected 200, got %d", rec2.Code)
	}
	var list listResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	if len(list.Data) != 1 {
		t.Fatalf("List: expected 1 todo, got %d", len(list.Data))
	}

	// GET
	req3 := httptest.NewRequest(http.MethodGet, "/api/todos/"+created.ID, nil)
	rec3 := httptest.NewRecorder()
	e.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("Get: expected 200, got %d", rec3.Code)
	}

	// UPDATE
	updateBody := `{"completed":true,"title":"updated sqlite todo"}`
	req4 := httptest.NewRequest(http.MethodPut, "/api/todos/"+created.ID, strings.NewReader(updateBody))
	req4.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec4 := httptest.NewRecorder()
	e.ServeHTTP(rec4, req4)

	if rec4.Code != http.StatusOK {
		t.Fatalf("Update: expected 200, got %d", rec4.Code)
	}
	var updated Todo
	if err := json.Unmarshal(rec4.Body.Bytes(), &updated); err != nil {
		t.Fatalf("unmarshal update response: %v", err)
	}
	if !updated.Completed {
		t.Fatal("todo should be completed after update")
	}
	if updated.Title != "updated sqlite todo" {
		t.Fatalf("expected title %q, got %q", "updated sqlite todo", updated.Title)
	}

	// DELETE
	req5 := httptest.NewRequest(http.MethodDelete, "/api/todos/"+created.ID, nil)
	rec5 := httptest.NewRecorder()
	e.ServeHTTP(rec5, req5)

	if rec5.Code != http.StatusNoContent {
		t.Fatalf("Delete: expected 204, got %d", rec5.Code)
	}

	// NOT FOUND
	req6 := httptest.NewRequest(http.MethodGet, "/api/todos/"+created.ID, nil)
	rec6 := httptest.NewRecorder()
	e.ServeHTTP(rec6, req6)

	if rec6.Code != http.StatusNotFound {
		t.Fatalf("Get after delete: expected 404, got %d", rec6.Code)
	}
}

func TestSQLiteStorePagination(t *testing.T) {
	store, err := NewSQLiteStore("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open in-memory sqlite: %v", err)
	}
	defer store.Close()

	e, _ := setupRouter(store)

	// Create 3 todos.
	for _, title := range []string{"alpha", "beta", "gamma"} {
		_, err := store.Create(title)
		if err != nil {
			t.Fatalf("create %q: %v", title, err)
		}
	}

	// Page 1: limit=2
	req := httptest.NewRequest(http.MethodGet, "/api/todos?limit=2", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Page 1: expected 200, got %d", rec.Code)
	}
	var p1 listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &p1); err != nil {
		t.Fatalf("unmarshal page 1: %v", err)
	}
	if len(p1.Data) != 2 {
		t.Fatalf("Page 1: expected 2 items, got %d", len(p1.Data))
	}
	if p1.Data[0].Title != "alpha" || p1.Data[1].Title != "beta" {
		t.Fatalf("Page 1: expected [alpha, beta], got [%s, %s]", p1.Data[0].Title, p1.Data[1].Title)
	}
	if p1.NextCursor == "" {
		t.Fatal("Page 1: expected non-empty nextCursor")
	}
	if !p1.HasMore {
		t.Fatal("Page 1: expected hasMore=true")
	}

	// Page 2: use nextCursor
	req2 := httptest.NewRequest(http.MethodGet, "/api/todos?cursor="+p1.NextCursor+"&limit=2", nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("Page 2: expected 200, got %d", rec2.Code)
	}
	var p2 listResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &p2); err != nil {
		t.Fatalf("unmarshal page 2: %v", err)
	}
	if len(p2.Data) != 1 {
		t.Fatalf("Page 2: expected 1 item, got %d", len(p2.Data))
	}
	if p2.Data[0].Title != "gamma" {
		t.Fatalf("Page 2: expected 'gamma', got %q", p2.Data[0].Title)
	}
	if p2.NextCursor != "" {
		t.Fatalf("Page 2: expected empty nextCursor, got %q", p2.NextCursor)
	}
	if p2.HasMore {
		t.Fatal("Page 2: expected hasMore=false")
	}
}
