package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// Standard API error codes.
const (
	ErrorValidation = "VALIDATION_ERROR"
	ErrorNotFound   = "NOT_FOUND"
	ErrorInternal   = "INTERNAL_ERROR"
	ErrorConflict   = "CONFLICT"
	ErrorRateLimit  = "RATE_LIMITED"
	ErrorForbidden  = "FORBIDDEN"
)

// ErrorResponse is the standard error envelope returned on non-2xx responses.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody holds the machine-readable code and human-readable message.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// apiError creates an *echo.HTTPError with the API error code embedded
// in the internal error so the custom HTTP error handler can extract it.
func apiError(code string, status int, message string) error {
	// We embed "CODE|message" so customHTTPErrorHandler can split cleanly.
	return echo.NewHTTPError(status, fmt.Sprintf("%s|%s", code, message))
}

// customHTTPErrorHandler is Echo's error handler that serialises every
// error as {"error":{"code":"...","message":"..."}}.
func customHTTPErrorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}

	code := ErrorInternal
	status := http.StatusInternalServerError
	message := "internal server error"

	var he *echo.HTTPError
	if errors.As(err, &he) {
		status = he.Code
		if msg, ok := he.Message.(string); ok {
			// Try to extract our embedded "CODE|human message" format.
			code, message = splitCode(msg)
		}
	}

	if !c.Response().Committed {
		c.JSON(status, ErrorResponse{
			Error: ErrorBody{Code: code, Message: message},
		})
	}
}

// splitCode tries to parse a "CODE|message" string. If it doesn't contain
// a pipe, it treats the whole string as the message and maps the status
// code to a default error code.
func splitCode(s string) (code, message string) {
	parts := strings.SplitN(s, "|", 2)
	if len(parts) == 2 && parts[0] != "" {
		return parts[0], parts[1]
	}
	return statusToCode(0), s // caller should fix up code later via statusToCode
}

// statusToCode maps an HTTP status to the conventional API error code.
func statusToCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return ErrorValidation
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return ErrorForbidden
	case http.StatusNotFound:
		return ErrorNotFound
	case http.StatusConflict:
		return ErrorConflict
	case http.StatusTooManyRequests:
		return ErrorRateLimit
	default:
		return ErrorInternal
	}
}
