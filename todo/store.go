package main

// ListParams controls cursor-based pagination and filtering. An empty Cursor
// starts from the beginning. Limit defaults to 20 in the handler; 0 means
// unlimited. When Completed is non-nil only matching items are returned.
type ListParams struct {
	Cursor    string // ISO 8601 timestamp of the last item from the previous page
	Limit     int    // maximum items to return (0 = unlimited)
	Completed *bool  // filter by completion status (nil = no filter)
}

// ListResult contains a page of todos and the cursor for the next page.
type ListResult struct {
	Items      []*Todo
	NextCursor string // non-empty when there are more items
}

// Store is the persistence interface for todos.
type Store interface {
	List(p ListParams) (*ListResult, error)
	Get(id string) (*Todo, error)
	Create(title string) (*Todo, error)
	Update(id string, req UpdateTodoRequest) (*Todo, error)
	Delete(id string) error
	DeleteCompleted() (int64, error)
}
