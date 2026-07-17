// Package service implements the Monopam development resolver and its HTTP API.
package service

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"time"
)

const (
	maxRequestBytes = 16 << 10
	maxRecordsBytes = 1 << 20
)

var errAccessDenied = errors.New("database access denied")

// ResolveRequest is the flat identity shape sent by Argus.
type ResolveRequest struct {
	Username  string `json:"username"`
	Database  string `json:"database"`
	ClientIP  string `json:"client_ip"`
	Protocol  string `json:"protocol"`
	RequestID string `json:"request_id"`
}

// Record is a development stand-in for a vault lookup and client-secret issue.
// Handle is the client-facing identity; Username is the backend database user.
type Record struct {
	Handle                string            `json:"handle"`
	Database              string            `json:"database"`
	Host                  string            `json:"host"`
	Port                  int               `json:"port"`
	Protocol              string            `json:"protocol"`
	Username              string            `json:"username"`
	Password              string            `json:"password"`
	ClientSecret          string            `json:"client_secret"`
	AuthMethod            string            `json:"auth_method"`
	Roles                 []string          `json:"roles"`
	PolicyTags            map[string]string `json:"policy_tags"`
	ClientSecretExpiresAt time.Time         `json:"client_secret_expires_at"`
}

// ResolveResponse is the flat credential shape consumed by Argus.
type ResolveResponse struct {
	Host                  string            `json:"host"`
	Port                  int               `json:"port"`
	Protocol              string            `json:"protocol"`
	Username              string            `json:"username"`
	Password              string            `json:"password"`
	ClientSecret          string            `json:"client_secret"`
	AuthMethod            string            `json:"auth_method"`
	Roles                 []string          `json:"roles"`
	PolicyTags            map[string]string `json:"policy_tags"`
	ClientSecretExpiresAt time.Time         `json:"client_secret_expires_at"`
}

type recordsFile struct {
	Records []Record `json:"records"`
}

// Store is an immutable in-memory view of the records file.
type Store struct {
	records []Record
	now     func() time.Time
}

// LoadStore strictly loads a bounded JSON records file.
func LoadStore(path string) (*Store, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat records file: %w", err)
	}
	if info.Size() > maxRecordsBytes {
		return nil, fmt.Errorf("records file exceeds %d bytes", maxRecordsBytes)
	}

	decoder := json.NewDecoder(io.LimitReader(file, maxRecordsBytes+1))
	decoder.DisallowUnknownFields()

	var contents recordsFile
	if err := decoder.Decode(&contents); err != nil {
		return nil, fmt.Errorf("decode records JSON: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode records JSON: %w", err)
	}
	if len(contents.Records) == 0 {
		return nil, errors.New("records file contains no records")
	}

	return NewStore(contents.Records), nil
}

// NewStore creates an immutable store from records.
func NewStore(records []Record) *Store {
	cloned := make([]Record, len(records))
	for i := range records {
		cloned[i] = cloneRecord(records[i])
	}
	return &Store{records: cloned, now: time.Now}
}

// Resolve selects exactly one record and enforces all secret-safety invariants.
func (s *Store) Resolve(request ResolveRequest) (ResolveResponse, error) {
	var matched *Record
	for i := range s.records {
		record := &s.records[i]
		handle := record.Handle
		if handle == "" {
			handle = record.Username
		}
		if handle != request.Username || record.Protocol != request.Protocol {
			continue
		}
		if request.Database != "" && record.Database != request.Database {
			continue
		}
		if matched != nil {
			return ResolveResponse{}, errAccessDenied
		}
		matched = record
	}

	if matched == nil || !validRecord(*matched, s.now()) {
		return ResolveResponse{}, errAccessDenied
	}

	roles := append([]string(nil), matched.Roles...)
	if roles == nil {
		roles = []string{}
	}
	policyTags := cloneMap(matched.PolicyTags)
	if policyTags == nil {
		policyTags = map[string]string{}
	}

	return ResolveResponse{
		Host:                  matched.Host,
		Port:                  matched.Port,
		Protocol:              matched.Protocol,
		Username:              matched.Username,
		Password:              matched.Password,
		ClientSecret:          matched.ClientSecret,
		AuthMethod:            matched.AuthMethod,
		Roles:                 roles,
		PolicyTags:            policyTags,
		ClientSecretExpiresAt: matched.ClientSecretExpiresAt,
	}, nil
}

func validRecord(record Record, now time.Time) bool {
	if record.Host == "" || record.Port < 1 || record.Port > 65535 || record.Protocol == "" || record.Username == "" {
		return false
	}
	if record.Password == "" || record.ClientSecret == "" || secretsEqual(record.Password, record.ClientSecret) {
		return false
	}
	return !record.ClientSecretExpiresAt.IsZero() && record.ClientSecretExpiresAt.After(now)
}

func secretsEqual(left, right string) bool {
	leftHash := sha256.Sum256([]byte(left))
	rightHash := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(leftHash[:], rightHash[:]) == 1
}

func cloneRecord(record Record) Record {
	record.Roles = append([]string(nil), record.Roles...)
	record.PolicyTags = cloneMap(record.PolicyTags)
	return record
}

func cloneMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

// Resolver supplies resolved targets to the HTTP layer.
type Resolver interface {
	Resolve(ResolveRequest) (ResolveResponse, error)
}

type handler struct {
	tokenHash [sha256.Size]byte
	resolver  Resolver
}

// NewHandler returns the service's HTTP handler.
func NewHandler(apiToken string, resolver Resolver) (http.Handler, error) {
	if apiToken == "" {
		return nil, errors.New("API token must not be empty")
	}
	if resolver == nil {
		return nil, errors.New("resolver must not be nil")
	}

	h := &handler{
		tokenHash: sha256.Sum256([]byte("Bearer " + apiToken)),
		resolver:  resolver,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/db/resolve", h.resolve)
	mux.HandleFunc("/healthz", health)
	return mux, nil
}

func (h *handler) resolve(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")

	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		writeError(response, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "only POST is allowed")
		return
	}
	if !h.authorized(request) {
		response.Header().Set("WWW-Authenticate", `Bearer realm="monopam"`)
		writeError(response, http.StatusUnauthorized, "UNAUTHORIZED", "valid bearer authentication is required")
		return
	}
	if !isJSON(request) {
		writeError(response, http.StatusBadRequest, "INVALID_REQUEST", "Content-Type must be application/json")
		return
	}

	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()

	var input ResolveRequest
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "INVALID_REQUEST", "request body must be one valid JSON object")
		return
	}
	if err := requireJSONEOF(decoder); err != nil {
		writeError(response, http.StatusBadRequest, "INVALID_REQUEST", "request body must contain exactly one JSON object")
		return
	}
	if input.Username == "" || input.Protocol == "" {
		writeError(response, http.StatusBadRequest, "INVALID_REQUEST", "username and protocol are required")
		return
	}

	resolved, err := h.resolver.Resolve(input)
	if err != nil {
		if errors.Is(err, errAccessDenied) {
			writeError(response, http.StatusForbidden, "ACCESS_DENIED", "database access denied")
			return
		}
		writeError(response, http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error")
		return
	}

	writeJSON(response, http.StatusOK, resolved)
}

func (h *handler) authorized(request *http.Request) bool {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	presentedHash := sha256.Sum256([]byte(values[0]))
	return subtle.ConstantTimeCompare(presentedHash[:], h.tokenHash[:]) == 1
}

func isJSON(request *http.Request) bool {
	values := request.Header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	return err == nil && mediaType == "application/json"
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func health(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeError(response, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "only GET is allowed")
		return
	}
	writeJSON(response, http.StatusOK, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(response http.ResponseWriter, status int, code, message string) {
	writeJSON(response, status, errorEnvelope{Error: apiError{Code: code, Message: message}})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
