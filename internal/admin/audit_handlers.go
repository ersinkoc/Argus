package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/ersinkoc/argus/internal/audit"
)

// SetAuditLogPath sets the audit log file path for search.
func (s *Server) SetAuditLogPath(path string) {
	s.auditLogPath = path
}

// Server.recordFile is the path to query recordings for replay.
func (s *Server) SetRecordFile(path string) {
	s.recordFile = path
}

func (s *Server) handleAuditSearch(w http.ResponseWriter, r *http.Request) {
	if s.auditLogPath == "" {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "audit log path not configured")
		return
	}

	q := r.URL.Query()
	filter := audit.SearchFilter{
		SessionID:   q.Get("session_id"),
		Username:    q.Get("username"),
		Database:    q.Get("database"),
		EventType:   q.Get("event_type"),
		Action:      q.Get("action"),
		CommandType: q.Get("command_type"),
	}
	if v := q.Get("limit"); v != "" {
		n := 0
		for _, c := range v {
			n = n*10 + int(c-'0')
		}
		filter.Limit = n
	}
	if v := q.Get("start"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.StartTime = t
		}
	}
	if v := q.Get("end"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.EndTime = t
		}
	}

	result, err := audit.SearchFile(s.auditLogPath, filter)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleReplay(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", "missing session_id parameter")
		return
	}
	path := s.recordFile
	if path == "" {
		path = s.auditLogPath
	}
	if path == "" {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "recording not configured")
		return
	}

	replay, err := audit.ReplayFromFile(path, sessionID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(replay)
}

func (s *Server) handleFingerprints(w http.ResponseWriter, r *http.Request) {
	path := s.recordFile
	if path == "" {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "recording not configured")
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		n := 0
		for _, c := range v {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		if n > 0 {
			limit = n
		}
	}

	top, err := audit.TopFingerprints(path, limit)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(top)
}

func (s *Server) handleCompact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}

	logDir := ""
	if s.auditLogPath != "" {
		logDir = filepath.Dir(s.auditLogPath)
	}
	if logDir == "" || logDir == "." {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "audit log path not configured")
		return
	}

	dryRun := r.URL.Query().Get("dry_run") == "true"
	maxAge := 7 * 24 * time.Hour
	if v := r.URL.Query().Get("max_age_hours"); v != "" {
		hours := 0
		for _, c := range v {
			if c >= '0' && c <= '9' {
				hours = hours*10 + int(c-'0')
			}
		}
		if hours > 0 {
			maxAge = time.Duration(hours) * time.Hour
		}
	}

	result, err := audit.CompactLogs(logDir, audit.CompactionConfig{
		MaxAge: maxAge,
		DryRun: dryRun,
	})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if s.auditLogPath == "" {
		writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "audit log path not configured")
		return
	}

	q := r.URL.Query()
	filter := audit.SearchFilter{
		Username: q.Get("username"),
		Action:   q.Get("action"),
		Limit:    1000,
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=argus-audit.csv")

	count, err := audit.ExportCSV(s.auditLogPath, w, filter)
	if err != nil {
		slog.Error("CSV export error", "error", err)
		return
	}
	slog.Info("CSV export completed", "count", count)
}
