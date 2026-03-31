package admin

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// TestRunRequest is the input for the test runner API.
type TestRunRequest struct {
	Name string `json:"name"`
	User string `json:"user"`
	DB   string `json:"db"` // "pg" or "mysql"
	SQL  string `json:"sql"`
}

// TestRunResponse is the output for the test runner API.
type TestRunResponse struct {
	User          string `json:"user"`
	Database      string `json:"database"`
	SQL           string `json:"sql"`
	Action        string `json:"action"` // "allow", "block", "mask"
	Rows          int    `json:"rows"`
	Duration      string `json:"duration"`
	Masked        bool   `json:"masked"`
	ColumnsMasked int    `json:"columns_masked"`
	Reason        string `json:"reason,omitempty"`
	Error         string `json:"error,omitempty"`
	Output        string `json:"output,omitempty"`
}

// TestRunnerConfig holds proxy addresses for the test runner.
type TestRunnerConfig struct {
	PGHost        string
	PGPort        int
	MySQLHost     string
	MySQLPort     int
	PGPassword    string
	MySQLUser     string
	MySQLPassword string
}

var testRunnerCfg *TestRunnerConfig

// SetTestRunnerConfig configures the test runner proxy addresses.
func SetTestRunnerConfig(cfg *TestRunnerConfig) {
	testRunnerCfg = cfg
}

func handleTestRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TestRunRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, TestRunResponse{Error: "invalid request: " + err.Error()})
		return
	}

	if req.SQL == "" {
		respondJSON(w, TestRunResponse{Error: "SQL is required"})
		return
	}

	cfg := testRunnerCfg
	if cfg == nil {
		respondJSON(w, TestRunResponse{Error: "test runner not configured"})
		return
	}

	start := time.Now()
	var resp TestRunResponse
	resp.User = req.User
	resp.SQL = req.SQL
	resp.Database = "testdb"

	switch req.DB {
	case "pg":
		resp = execPG(cfg, req.User, req.SQL, resp)
	case "mysql":
		resp = execMySQL(cfg, req.SQL, resp)
	default:
		resp.Error = "unknown db type: " + req.DB
	}

	resp.Duration = time.Since(start).Round(time.Millisecond).String()
	respondJSON(w, resp)
}

func execPG(cfg *TestRunnerConfig, user, sql string, resp TestRunResponse) TestRunResponse {
	// Use docker exec + psql through the proxy
	args := []string{
		"exec", "-e", "PGPASSWORD=" + cfg.PGPassword,
		"argus-postgres-1", "psql",
		"-h", cfg.PGHost, "-p", itoa(cfg.PGPort),
		"-U", user, "-d", "testdb",
		"-q", "-t", "-c", sql,
	}

	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))

	if err != nil {
		// Check if it's a policy block
		if strings.Contains(output, "Access denied:") {
			resp.Action = "block"
			// Extract reason after "Access denied: "
			if idx := strings.Index(output, "Access denied: "); idx >= 0 {
				resp.Reason = output[idx+15:]
				if end := strings.Index(resp.Reason, "\n"); end > 0 {
					resp.Reason = resp.Reason[:end]
				}
			}
			return resp
		}
		if strings.Contains(output, "DELETE without WHERE") || strings.Contains(output, "prohibited") {
			resp.Action = "block"
			resp.Reason = output
			return resp
		}
		resp.Error = output
		return resp
	}

	// Count rows from output
	lines := strings.Split(output, "\n")
	rows := 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && l != "(" {
			rows++
		}
	}
	resp.Rows = rows
	resp.Output = output

	// Check for masked data (*** pattern)
	if strings.Contains(output, "***") {
		resp.Action = "mask"
		resp.Masked = true
		resp.ColumnsMasked = strings.Count(output, "***")
	} else {
		resp.Action = "allow"
	}

	return resp
}

func execMySQL(cfg *TestRunnerConfig, sql string, resp TestRunResponse) TestRunResponse {
	args := []string{
		"exec", "argus-mysql-1", "mariadb",
		"-h", cfg.MySQLHost, "-P", itoa(cfg.MySQLPort),
		"-u", cfg.MySQLUser, "-p" + cfg.MySQLPassword,
		"--skip-ssl", "-s", "testdb",
		"-e", sql,
	}

	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))

	if err != nil {
		resp.Error = output
		return resp
	}

	lines := strings.Split(output, "\n")
	rows := 0
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			rows++
		}
	}
	resp.Rows = rows
	resp.Output = output
	resp.Action = "allow"

	return resp
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 6)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func respondJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
