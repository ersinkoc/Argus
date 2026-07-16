package main

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"

	_ "modernc.org/sqlite"
)

// SQLiteStore is a SQLite-backed todo store.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (or creates) the SQLite database at path and
// returns a store backed by it.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// WAL mode for better concurrent read performance.
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return nil, fmt.Errorf("enable WAL: %w", err)
	}

	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

// Close shuts down the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Ping checks whether the database connection is still alive.
func (s *SQLiteStore) Ping() error {
	return s.db.Ping()
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS todos (
			id         TEXT PRIMARY KEY,
			title      TEXT    NOT NULL,
			completed  INTEGER NOT NULL DEFAULT 0,
			created_at TEXT    NOT NULL,
			updated_at TEXT    NOT NULL
		)
	`)
	return err
}

// List returns todos ordered by creation time (oldest first), with
// optional cursor-based pagination and completed filter.
func (s *SQLiteStore) List(p ListParams) (*ListResult, error) {
	query := `SELECT id, title, completed, created_at, updated_at
		   FROM todos`
	args := make([]any, 0)
	var wheres []string

	if p.Cursor != "" {
		wheres = append(wheres, `created_at > ?`)
		args = append(args, p.Cursor)
	}
	if p.Completed != nil {
		wheres = append(wheres, `completed = ?`)
		args = append(args, boolToInt(*p.Completed))
	}

	if len(wheres) > 0 {
		query += ` WHERE `
		for i, w := range wheres {
			if i > 0 {
				query += ` AND `
			}
			query += w
		}
	}
	query += ` ORDER BY created_at ASC`

	limit := p.Limit
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit+1) // fetch one extra for hasMore detection
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list todos: %w", err)
	}
	defer rows.Close()

	var todos []*Todo
	for rows.Next() {
		t, err := scanTodo(rows)
		if err != nil {
			return nil, err
		}
		todos = append(todos, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate todos: %w", err)
	}

	nextCursor := ""
	hasMore := false
	if limit > 0 && len(todos) > limit {
		hasMore = true
		todos = todos[:limit]
	}
	if hasMore && len(todos) > 0 {
		nextCursor = todos[len(todos)-1].CreatedAt.Format(time.RFC3339Nano)
	}
	if todos == nil {
		todos = []*Todo{}
	}
	return &ListResult{Items: todos, NextCursor: nextCursor}, nil
}

// Get returns a single todo by ID.
func (s *SQLiteStore) Get(id string) (*Todo, error) {
	row := s.db.QueryRow(
		`SELECT id, title, completed, created_at, updated_at
		   FROM todos WHERE id = ?`, id)
	t, err := scanTodo(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("todo %q not found", id)
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

// Create adds a new todo with the given title.
func (s *SQLiteStore) Create(title string) (*Todo, error) {
	now := time.Now().UTC()
	t := &Todo{
		ID:        uuid.NewString(),
		Title:     title,
		Completed: false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	_, err := s.db.Exec(
		`INSERT INTO todos (id, title, completed, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		t.ID, t.Title, boolToInt(t.Completed),
		t.CreatedAt.Format(time.RFC3339Nano),
		t.UpdatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("create todo: %w", err)
	}
	return t, nil
}

// Update modifies an existing todo. Only non-nil fields are applied.
func (s *SQLiteStore) Update(id string, req UpdateTodoRequest) (*Todo, error) {
	// Fetch current state first so we return the full object.
	cur, err := s.Get(id)
	if err != nil {
		return nil, err // not found propagates as-is
	}

	if req.Title != nil {
		cur.Title = *req.Title
	}
	if req.Completed != nil {
		cur.Completed = *req.Completed
	}
	cur.UpdatedAt = time.Now().UTC()

	_, err = s.db.Exec(
		`UPDATE todos
		    SET title = ?, completed = ?, updated_at = ?
		  WHERE id = ?`,
		cur.Title, boolToInt(cur.Completed),
		cur.UpdatedAt.Format(time.RFC3339Nano), id)
	if err != nil {
		return nil, fmt.Errorf("update todo: %w", err)
	}
	return cur, nil
}

// Delete removes a todo by ID.
func (s *SQLiteStore) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM todos WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete todo: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("todo %q not found", id)
	}
	return nil
}

// DeleteCompleted removes all completed todos and returns the count.
func (s *SQLiteStore) DeleteCompleted() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM todos WHERE completed = 1`)
	if err != nil {
		return 0, fmt.Errorf("delete completed: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// --- helpers ---

// rowScanner matches both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanTodo(rs rowScanner) (*Todo, error) {
	var (
		id, title, createdAtStr, updatedAtStr string
		completed                             int
	)
	if err := rs.Scan(&id, &title, &completed, &createdAtStr, &updatedAtStr); err != nil {
		return nil, err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("parse created_at %q: %w", createdAtStr, err)
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, updatedAtStr)
	if err != nil {
		return nil, fmt.Errorf("parse updated_at %q: %w", updatedAtStr, err)
	}
	return &Todo{
		ID:        id,
		Title:     title,
		Completed: completed != 0,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
