package admin

import (
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"
)

//go:embed adminui/*
var adminUIFiles embed.FS

// adminUIHandler serves the React admin UI with SPA fallback.
// It first tries to serve a file matching the request path from the embedded FS,
// and falls back to serving index.html for SPA client-side routing.
type adminUIHandler struct {
	fs     http.FileSystem
	prefix string
}

// NewAdminUIHandler creates a handler that serves the embedded React admin UI.
// If the admin UI hasn't been built yet (embedded FS is empty), it checks for
// a local dist directory, then falls back to the old dashboard.
func NewAdminUIHandler(prefix string) http.Handler {
	// Try to use the embedded files
	subFS, err := fs.Sub(adminUIFiles, "adminui")
	if err == nil {
		// Check if there are actual files embedded (not just empty dir)
		_, err := fs.ReadDir(subFS, ".")
		if err == nil {
			slog.Info("serving embedded admin UI", "prefix", prefix)
			return &adminUIHandler{
				fs:     http.FS(subFS),
				prefix: prefix,
			}
		}
	}

	// Fallback: try to serve from local dist directory (dev mode)
	devDist := "../admin-ui/dist"
	if _, err := os.Stat(devDist); err == nil {
		slog.Info("serving dev admin UI from local dist", "path", devDist)
		return &adminUIHandler{
			fs:     http.Dir(devDist),
			prefix: prefix,
		}
	}

	return nil
}

func (h *adminUIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Determine the file path
	filePath := strings.TrimPrefix(r.URL.Path, h.prefix)
	if filePath == "" || filePath == "/" {
		filePath = "/index.html"
	}

	// Try to open the file
	f, err := h.fs.Open(strings.TrimPrefix(filePath, "/"))
	if err != nil {
		// SPA fallback: serve index.html for client-side routing
		f, err = h.fs.Open("index.html")
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		filePath = "/index.html"
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Set proper content type based on extension
	ext := path.Ext(filePath)
	switch ext {
	case ".js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	case ".json":
		w.Header().Set("Content-Type", "application/json")
	case ".map":
		w.Header().Set("Content-Type", "application/json")
	}

	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	http.ServeContent(w, r, filePath, stat.ModTime(), f)
}
