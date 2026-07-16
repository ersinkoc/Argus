package main

import (
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	dbPath := os.Getenv("TODO_DB_PATH")
	if dbPath == "" {
		dbPath = "todos.db"
	}

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		panic("failed to open store: " + err.Error())
	}
	defer store.Close()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	timeout := 30 * time.Second
	if t := os.Getenv("REQUEST_TIMEOUT"); t != "" {
		if d, err := time.ParseDuration(t); err == nil && d > 0 {
			timeout = d
		}
	}

	logger := newLogger()
	e := echo.New()
	initEchoLogger(e, logger)
	e.HTTPErrorHandler = customHTTPErrorHandler

	// ----- Middleware -----
	e.Use(middleware.RequestID())
	e.Use(slogAccessLog(logger))
	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: timeout,
	}))
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderXRequestID},
	}))

	// ----- Handlers -----
	h := NewHandlers(store)

	// ----- Routes -----
	e.GET("/health", h.HealthCheck)

	api := e.Group("/api/todos")
	api.GET("", h.ListTodos)
	api.POST("", h.CreateTodo)
	api.DELETE("", h.DeleteCompletedTodos) // batch delete — must be before :id
	api.GET("/:id", h.GetTodo)
	api.PUT("/:id", h.UpdateTodo)
	api.DELETE("/:id", h.DeleteTodo)

	// ----- Start -----
	addr := ":" + port
	logger.Info("starting server", "addr", addr, "db", dbPath)
	if err := e.Start(addr); err != nil {
		logger.Error("server failed", "error", err)
	}
}
