package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
)

// newLogger creates the application-wide structured logger.
func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

// discardWriter is an io.Writer that discards everything. Used to mute Echo's
// built-in logger output since we handle access logs ourselves.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// slogAccessLog is an Echo middleware that logs every request via slog in
// structured JSON format.
func slogAccessLog(logger *slog.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			req := c.Request()

			err := next(c)

			// Echo initialises Response.Status to 200. If the response hasn't
			// been committed yet, the handler returned an error and the HTTP
			// error handler will set the real status. Extract it from the
			// error in that case.
			status := c.Response().Status
			if !c.Response().Committed && err != nil {
				status = http.StatusInternalServerError
				var he *echo.HTTPError
				if errors.As(err, &he) {
					status = he.Code
				}
			}

			attrs := []slog.Attr{
				slog.String("method", req.Method),
				slog.String("path", req.URL.Path),
				slog.Int("status", status),
				slog.String("latency", time.Since(start).String()),
				slog.String("ip", c.RealIP()),
				slog.String("id", c.Response().Header().Get(echo.HeaderXRequestID)),
			}
			if err != nil {
				attrs = append(attrs, slog.String("error", err.Error()))
			}

			level := slog.LevelInfo
			if status >= 500 {
				level = slog.LevelError
			} else if status >= 400 {
				level = slog.LevelWarn
			}

			logger.LogAttrs(context.Background(), level, "request", attrs...)

			return err
		}
	}
}

// initEchoLogger configures Echo's internal logger to output through slog.
// The access log middleware is replaced with our slog-based one.
func initEchoLogger(e *echo.Echo, logger *slog.Logger) {
	// Discard Echo's default text output — we use slogAccessLog instead.
	e.Logger.SetOutput(&discardWriter{})
}
