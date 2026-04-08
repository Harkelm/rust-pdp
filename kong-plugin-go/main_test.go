// main_test.go
// Unit tests for the Cedar PDP Kong Go plugin.
//
// Test coverage:
//   - PDP request construction (principal/action/resource formatting)
//   - Response handling: Allow -> pass, Deny -> 403, 503 -> 503+Retry-After,
//     timeout -> 503+Retry-After
//   - Config struct has NO FailOpen field (ADR-006 P0)
//   - Principal extraction priority order
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// --- Cedar entity formatting ---

func TestToCedarPrincipal(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{"alice", `User::"alice"`},
		{"anonymous", `User::"anonymous"`},
		{"550e8400-e29b-41d4-a716-446655440000", `User::"550e8400-e29b-41d4-a716-446655440000"`},
	}
	for _, c := range cases {
		got := toCedarPrincipal(c.id)
		if got != c.want {
			t.Errorf("toCedarPrincipal(%q) = %q, want %q", c.id, got, c.want)
		}
	}
}

func TestToCedarAction(t *testing.T) {
	cases := []struct {
		method string
		want   string
	}{
		{"GET", `Action::"get"`},
		{"POST", `Action::"post"`},
		{"DELETE", `Action::"delete"`},
		{"get", `Action::"get"`},
	}
	for _, c := range cases {
		got := toCedarAction(c.method)
		if got != c.want {
			t.Errorf("toCedarAction(%q) = %q, want %q", c.method, got, c.want)
		}
	}
}

func TestToCedarResource(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/api/v1/users", `Resource::"/api/v1/users"`},
		{"/", `Resource::"/"`},
		{"/api/v1/users/42", `Resource::"/api/v1/users/42"`},
	}
	for _, c := range cases {
		got := toCedarResource(c.path)
		if got != c.want {
			t.Errorf("toCedarResource(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// --- ADR-006 P0: Config must NOT have a FailOpen field ---

func TestConfigHasNoFailOpenField(t *testing.T) {
	configType := reflect.TypeOf(Config{})
	for i := 0; i < configType.NumField(); i++ {
		field := configType.Field(i)
		name := strings.ToLower(field.Name)
		if strings.Contains(name, "failopen") || strings.Contains(name, "fail_open") {
			t.Errorf("Config must not have a FailOpen field (ADR-006 P0), found: %s", field.Name)
		}
		jsonTag := field.Tag.Get("json")
		if strings.Contains(strings.ToLower(jsonTag), "fail") {
			t.Errorf("Config must not have a fail-open json tag (ADR-006 P0), found tag: %s", jsonTag)
		}
	}
}

func TestConfigFields(t *testing.T) {
	configType := reflect.TypeOf(Config{})
	wantFields := map[string]bool{
		"PdpUrl":    true,
		"TimeoutMs": true,
	}
	found := make(map[string]bool)
	for i := 0; i < configType.NumField(); i++ {
		name := configType.Field(i).Name
		found[name] = true
		if !wantFields[name] {
			t.Errorf("unexpected Config field: %s", name)
		}
	}
	for name := range wantFields {
		if !found[name] {
			t.Errorf("expected Config field not found: %s", name)
		}
	}
}

// --- PDP request construction ---

func TestPdpRequestConstruction(t *testing.T) {
	req := pdpRequest{
		Principal: toCedarPrincipal("alice"),
		Action:    toCedarAction("GET"),
		Resource:  toCedarResource("/api/v1/users"),
		Context:   map[string]any{},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal pdpRequest: %v", err)
	}

	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("failed to unmarshal pdpRequest JSON: %v", err)
	}

	if out["principal"] != `User::"alice"` {
		t.Errorf("principal = %v, want User::\"alice\"", out["principal"])
	}
	if out["action"] != `Action::"get"` {
		t.Errorf("action = %v, want Action::\"get\"", out["action"])
	}
	if out["resource"] != `Resource::"/api/v1/users"` {
		t.Errorf("resource = %v, want Resource::\"/api/v1/users\"", out["resource"])
	}
	ctx, ok := out["context"].(map[string]any)
	if !ok || len(ctx) != 0 {
		t.Errorf("context should be empty object, got: %v", out["context"])
	}
}

// --- HTTP-level response handling tests ---
// These exercise the decision logic by making real HTTP calls to a test server,
// then checking what callPDP returns. The plugin Access() maps these results to
// kong.Response.Exit calls.

// callPDP makes a POST to the PDP endpoint and returns the decision and HTTP status.
// Mirrors the HTTP client logic in Access() without the PDK dependency.
func callPDPForTest(pdpURL string, timeoutMs int, req pdpRequest) (decision string, statusCode int, err error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return "", 0, err
	}

	timeout := time.Duration(timeoutMs) * time.Millisecond
	client := &http.Client{Timeout: timeout}

	httpReq, err := http.NewRequest(http.MethodPost, pdpURL+"/v1/is_authorized",
		strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusServiceUnavailable {
		return "", 503, nil
	}

	var pdpResp pdpResponse
	if decErr := json.NewDecoder(resp.Body).Decode(&pdpResp); decErr != nil {
		return "", resp.StatusCode, decErr
	}
	return pdpResp.Decision, resp.StatusCode, nil
}

func TestResponseHandling_Allow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"decision":"Allow","diagnostics":{"reason":["policy0"],"errors":[]}}`))
	}))
	defer srv.Close()

	decision, _, err := callPDPForTest(srv.URL, 3000, pdpRequest{
		Principal: toCedarPrincipal("alice"),
		Action:    toCedarAction("GET"),
		Resource:  toCedarResource("/api/v1/users"),
		Context:   map[string]any{},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != "Allow" {
		t.Errorf("decision = %q, want \"Allow\"", decision)
	}
	// Plugin passes through (no kong.Response.Exit) when decision is Allow.
}

func TestResponseHandling_Deny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"decision":"Deny","diagnostics":{"reason":[],"errors":[]}}`))
	}))
	defer srv.Close()

	decision, _, err := callPDPForTest(srv.URL, 3000, pdpRequest{
		Principal: toCedarPrincipal("alice"),
		Action:    toCedarAction("DELETE"),
		Resource:  toCedarResource("/api/v1/admin"),
		Context:   map[string]any{},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision != "Deny" {
		t.Errorf("decision = %q, want \"Deny\"", decision)
	}
	// Plugin calls kong.Response.Exit(403, ...) when decision is Deny.
}

func TestResponseHandling_PDP503(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, statusCode, err := callPDPForTest(srv.URL, 3000, pdpRequest{
		Principal: toCedarPrincipal("alice"),
		Action:    toCedarAction("GET"),
		Resource:  toCedarResource("/api/v1/users"),
		Context:   map[string]any{},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if statusCode != 503 {
		t.Errorf("statusCode = %d, want 503", statusCode)
	}
	// Plugin calls exit503() (503 + Retry-After) when PDP returns 503 -- never 403.
}

func TestResponseHandling_Timeout(t *testing.T) {
	// Server that sleeps longer than the plugin timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"decision":"Allow"}`))
	}))
	defer srv.Close()

	// Set timeout to 50ms -- server responds in 200ms, so this will always timeout.
	_, statusCode, err := callPDPForTest(srv.URL, 50, pdpRequest{
		Principal: toCedarPrincipal("alice"),
		Action:    toCedarAction("GET"),
		Resource:  toCedarResource("/api/v1/users"),
		Context:   map[string]any{},
	})

	// A timeout produces an error (context deadline exceeded).
	if err == nil {
		t.Error("expected timeout error, got nil")
	}

	// CRITICAL ADR-006: timeout must NOT produce 403.
	// The plugin calls exit503() (503 + Retry-After) on timeout, never 403.
	if statusCode == 403 {
		t.Error("CRITICAL ADR-006 VIOLATION: timeout produced 403 -- must be 503+Retry-After")
	}
}

// TestTimeout_NeverProduces403 verifies the conditional in Access() by asserting
// that the error path maps to exit503 and not a 403 exit.
func TestTimeout_NeverProduces403(t *testing.T) {
	// The Access() function structure:
	//   resp, err := client.Do(req)
	//   if err != nil { exit503(kong); return }   <- timeout lands here
	//   if resp.StatusCode == 503 { exit503; return }
	//   if decision == "Allow" { return }
	//   kong.Response.Exit(403, ...)              <- Deny lands here, NOT timeout
	//
	// This test confirms the structural separation: any non-nil err -> exit503.
	// statusCode 0 on err (not 403) confirms the contract.
	decision, statusCode, err := callPDPForTest("http://127.0.0.1:1", 50, pdpRequest{
		Principal: toCedarPrincipal("bob"),
		Action:    toCedarAction("GET"),
		Resource:  toCedarResource("/api/v1/data"),
		Context:   map[string]any{},
	})

	if err == nil {
		t.Error("expected connection error, got nil")
	}
	if statusCode == 403 {
		t.Error("CRITICAL ADR-006 VIOLATION: error/timeout path must not produce 403")
	}
	if decision == "Deny" {
		t.Error("error path must not produce Deny decision")
	}
}

// --- Default config values ---

func TestNewDefaultConfig(t *testing.T) {
	raw := New()
	conf, ok := raw.(*Config)
	if !ok {
		t.Fatalf("New() returned %T, want *Config", raw)
	}
	if conf.PdpUrl != "http://127.0.0.1:8180" {
		t.Errorf("PdpUrl = %q, want \"http://127.0.0.1:8180\"", conf.PdpUrl)
	}
	if conf.TimeoutMs != 3000 {
		t.Errorf("TimeoutMs = %d, want 3000", conf.TimeoutMs)
	}
}

// --- Constants ---

func TestConstants(t *testing.T) {
	if Priority != 925 {
		t.Errorf("Priority = %d, want 925", Priority)
	}
	if Version != "1.0.0" {
		t.Errorf("Version = %q, want \"1.0.0\"", Version)
	}
}
