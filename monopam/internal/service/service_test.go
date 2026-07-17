package service

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const testToken = "test-api-token"

func TestResolveHTTPArgusCompatibleShapeAndSeparateSecrets(t *testing.T) {
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	record := validTestRecord(expires)
	h := mustHandler(t, NewStore([]Record{record}))

	response := performResolve(h, testToken, `{
		"username":"client-handle",
		"database":"appdb",
		"client_ip":"192.0.2.4",
		"protocol":"postgresql",
		"request_id":"req-42"
	}`)
	defer response.Result().Body.Close()

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	var raw map[string]json.RawMessage
	decodeJSON(t, response.Result().Body, &raw)
	wantKeys := []string{
		"host", "port", "protocol", "username", "password", "client_secret",
		"auth_method", "roles", "policy_tags", "client_secret_expires_at",
	}
	if len(raw) != len(wantKeys) {
		t.Fatalf("response fields = %v, want exactly %v", mapKeys(raw), wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("response missing field %q", key)
		}
	}

	var got ResolveResponse
	remarshalDecode(t, raw, &got)
	if got.Password != record.Password {
		t.Errorf("password changed: got %q, want %q", got.Password, record.Password)
	}
	if got.ClientSecret != record.ClientSecret {
		t.Errorf("client_secret changed: got %q, want %q", got.ClientSecret, record.ClientSecret)
	}
	if got.Password == got.ClientSecret {
		t.Error("backend and client-leg secrets must be different")
	}
	if got.Host != record.Host || got.Port != record.Port || got.Protocol != record.Protocol || got.Username != record.Username {
		t.Errorf("resolved target = %#v, want record target %#v", got, record)
	}
	if !got.ClientSecretExpiresAt.Equal(expires) {
		t.Errorf("client_secret_expires_at = %s, want %s", got.ClientSecretExpiresAt, expires)
	}
}

func TestResolveHTTPRejectsBearerAuthenticationFailures(t *testing.T) {
	h := mustHandler(t, NewStore([]Record{validTestRecord(time.Now().Add(time.Hour))}))

	for _, test := range []struct {
		name   string
		header []string
	}{
		{name: "missing"},
		{name: "wrong token", header: []string{"Bearer wrong"}},
		{name: "wrong scheme", header: []string{"bearer " + testToken}},
		{name: "extra whitespace", header: []string{"Bearer  " + testToken}},
		{name: "multiple values", header: []string{"Bearer " + testToken, "Bearer " + testToken}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/db/resolve", strings.NewReader(validRequestJSON))
			request.Header.Set("Content-Type", "application/json")
			for _, value := range test.header {
				request.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)

			assertAPIError(t, response, http.StatusUnauthorized, "UNAUTHORIZED")
			if got := response.Header().Get("WWW-Authenticate"); got == "" {
				t.Error("401 response is missing WWW-Authenticate")
			}
		})
	}
}

func TestResolveHTTPRejectsMalformedRequests(t *testing.T) {
	h := mustHandler(t, NewStore([]Record{validTestRecord(time.Now().Add(time.Hour))}))

	for _, test := range []struct {
		name        string
		contentType string
		body        string
	}{
		{name: "missing content type", body: validRequestJSON},
		{name: "wrong content type", contentType: "text/plain", body: validRequestJSON},
		{name: "unknown field", contentType: "application/json", body: `{"username":"client-handle","database":"appdb","protocol":"postgresql","surprise":true}`},
		{name: "malformed JSON", contentType: "application/json", body: `{"username":`},
		{name: "trailing object", contentType: "application/json", body: validRequestJSON + `{}`},
		{name: "missing required field", contentType: "application/json", body: `{"username":"client-handle","database":"appdb"}`},
		{name: "oversized", contentType: "application/json", body: `{"username":"` + strings.Repeat("a", maxRequestBytes) + `","database":"appdb","protocol":"postgresql"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/db/resolve", strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer "+testToken)
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			h.ServeHTTP(response, request)
			assertAPIError(t, response, http.StatusBadRequest, "INVALID_REQUEST")
		})
	}
}

func TestResolveHTTPRejectsUnsafeRecordsWithoutEchoingSecrets(t *testing.T) {
	fixedNow := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, test := range []struct {
		name   string
		mutate func(*Record)
	}{
		{name: "expired client secret", mutate: func(record *Record) { record.ClientSecretExpiresAt = fixedNow }},
		{name: "same secrets", mutate: func(record *Record) { record.ClientSecret = record.Password }},
		{name: "empty client secret", mutate: func(record *Record) { record.ClientSecret = "" }},
		{name: "empty backend password", mutate: func(record *Record) { record.Password = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := validTestRecord(fixedNow.Add(time.Hour))
			test.mutate(&record)
			store := NewStore([]Record{record})
			store.now = func() time.Time { return fixedNow }
			h := mustHandler(t, store)

			response := performResolve(h, testToken, validRequestJSON)
			assertAPIError(t, response, http.StatusForbidden, "ACCESS_DENIED")
			body := response.Body.String()
			if strings.Contains(body, "backend-only-secret") || strings.Contains(body, "client-only-secret") {
				t.Fatalf("denial response leaked a secret: %s", body)
			}
		})
	}
}

func TestResolveHTTPUnknownRecordIsForbidden(t *testing.T) {
	h := mustHandler(t, NewStore([]Record{validTestRecord(time.Now().Add(time.Hour))}))
	response := performResolve(h, testToken, `{"username":"unknown","database":"appdb","protocol":"postgresql"}`)
	assertAPIError(t, response, http.StatusForbidden, "ACCESS_DENIED")
}

func TestResolveHTTPAllowsUniqueEmptyDatabaseForMSSQL(t *testing.T) {
	record := validTestRecord(time.Now().Add(time.Hour))
	record.Protocol = "mssql"
	record.Database = "inventory"
	record.Port = 1433
	h := mustHandler(t, NewStore([]Record{record}))

	response := performResolve(h, testToken, `{"username":"client-handle","database":"","protocol":"mssql"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got ResolveResponse
	decodeJSON(t, response.Result().Body, &got)
	if got.Protocol != "mssql" || got.Port != 1433 {
		t.Errorf("resolved target = %#v, want unique MSSQL target", got)
	}
}

func TestResolveHTTPDeniesAmbiguousEmptyDatabase(t *testing.T) {
	first := validTestRecord(time.Now().Add(time.Hour))
	second := first
	second.Database = "otherdb"
	second.Host = "other-db.internal"
	h := mustHandler(t, NewStore([]Record{first, second}))

	response := performResolve(h, testToken, `{"username":"client-handle","protocol":"postgresql"}`)
	assertAPIError(t, response, http.StatusForbidden, "ACCESS_DENIED")
}

func TestResolveHTTPMethodAndUnexpectedFailure(t *testing.T) {
	t.Run("method", func(t *testing.T) {
		h := mustHandler(t, NewStore([]Record{validTestRecord(time.Now().Add(time.Hour))}))
		request := httptest.NewRequest(http.MethodGet, "/api/db/resolve", nil)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		assertAPIError(t, response, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		if got := response.Header().Get("Allow"); got != http.MethodPost {
			t.Errorf("Allow = %q, want POST", got)
		}
	})

	t.Run("unexpected resolver error", func(t *testing.T) {
		h := mustHandler(t, failingResolver{})
		response := performResolve(h, testToken, validRequestJSON)
		assertAPIError(t, response, http.StatusInternalServerError, "INTERNAL_ERROR")
		if strings.Contains(response.Body.String(), "private failure detail") {
			t.Fatalf("internal error leaked resolver detail: %s", response.Body.String())
		}
	})
}

func TestLoadStoreStrictJSON(t *testing.T) {
	path := t.TempDir() + "/records.json"
	contents := `{"records":[{
		"handle":"client-handle","database":"appdb","host":"db.internal","port":5432,
		"protocol":"postgresql","username":"backend-user","password":"backend-only-secret",
		"client_secret":"client-only-secret","auth_method":"scram_sha_256","roles":[],
		"policy_tags":{},"client_secret_expires_at":"2099-01-01T00:00:00Z"
	}]}`
	if err := osWriteFile(path, contents); err != nil {
		t.Fatal(err)
	}
	store, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore() error = %v", err)
	}
	if _, err := store.Resolve(ResolveRequest{Username: "client-handle", Database: "appdb", Protocol: "postgresql"}); err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}

	if err := osWriteFile(path, `{"records":[],"unknown":true}`); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStore(path); err == nil {
		t.Error("LoadStore accepted an unknown field")
	}
}

func TestHealth(t *testing.T) {
	h := mustHandler(t, NewStore([]Record{validTestRecord(time.Now().Add(time.Hour))}))
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatalf("health response = status %d body %q", response.Code, response.Body.String())
	}
}

const validRequestJSON = `{"username":"client-handle","database":"appdb","client_ip":"192.0.2.4","protocol":"postgresql","request_id":"req-42"}`

func validTestRecord(expires time.Time) Record {
	return Record{
		Handle:                "client-handle",
		Database:              "appdb",
		Host:                  "db.internal",
		Port:                  5432,
		Protocol:              "postgresql",
		Username:              "backend-user",
		Password:              "backend-only-secret",
		ClientSecret:          "client-only-secret",
		AuthMethod:            "scram_sha_256",
		Roles:                 []string{"application"},
		PolicyTags:            map[string]string{"environment": "test"},
		ClientSecretExpiresAt: expires,
	}
}

func mustHandler(t *testing.T, resolver Resolver) http.Handler {
	t.Helper()
	h, err := NewHandler(testToken, resolver)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return h
}

func performResolve(h http.Handler, token, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/db/resolve", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	return response
}

func assertAPIError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, status, response.Body.String())
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var envelope errorEnvelope
	decodeJSON(t, response.Result().Body, &envelope)
	if envelope.Error.Code != code || envelope.Error.Message == "" {
		t.Errorf("error = %#v, want code %q with a message", envelope.Error, code)
	}
}

func decodeJSON(t *testing.T, reader io.Reader, target any) {
	t.Helper()
	if err := json.NewDecoder(reader).Decode(target); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func remarshalDecode(t *testing.T, value, target any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}
}

func mapKeys(values map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

type failingResolver struct{}

func (failingResolver) Resolve(ResolveRequest) (ResolveResponse, error) {
	return ResolveResponse{}, errors.New("private failure detail")
}

func osWriteFile(path, contents string) error {
	return os.WriteFile(path, []byte(contents), 0o600)
}
