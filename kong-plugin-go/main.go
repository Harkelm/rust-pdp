// main.go
// Kong Go external plugin: Cedar PDP authorization callout
//
// Phase: access
// Priority: 925 (after auth plugins at 950, before rate limiting)
//
// Extracts principal + request context, POSTs to Cedar PDP sidecar,
// enforces the decision per ADR-006 (no fail-open, 503+Retry-After
// for PDP unavailability).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
)

// Shared HTTP client -- reuses connections across requests (keep-alive).
var pdpClient = &http.Client{}

const Version = "1.0.0"
const Priority = 925

// Config holds the plugin configuration fields.
// FailOpen is explicitly absent per ADR-006 P0 security requirement.
type Config struct {
	PdpUrl    string `json:"pdp_url"`
	TimeoutMs int    `json:"timeout_ms"`
}

// New returns a default Config used as the plugin factory.
func New() interface{} {
	return &Config{
		PdpUrl:    "http://127.0.0.1:8180",
		TimeoutMs: 3000,
	}
}

// pdpRequest is the JSON body sent to the Cedar PDP.
type pdpRequest struct {
	Principal string         `json:"principal"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Context   map[string]any `json:"context"`
}

// pdpResponse is the JSON body returned by the Cedar PDP on 200 OK.
type pdpResponse struct {
	Decision    string      `json:"decision"`
	Diagnostics interface{} `json:"diagnostics,omitempty"`
}

// getPrincipal resolves the caller identity in priority order:
//  1. Kong consumer set by upstream auth plugin
//  2. X-Consumer-ID request header
//  3. Literal "anonymous"
func getPrincipal(kong *pdk.PDK) (string, error) {
	consumer, err := kong.Client.GetConsumer()
	if err == nil && consumer.Id != "" {
		return consumer.Id, nil
	}

	headerID, err := kong.Request.GetHeader("X-Consumer-ID")
	if err == nil && headerID != "" {
		return headerID, nil
	}

	return "anonymous", nil
}

// toCedarPrincipal formats an ID as a Cedar entity UID: User::"<id>"
func toCedarPrincipal(id string) string {
	return fmt.Sprintf(`User::"%s"`, id)
}

// toCedarAction formats an HTTP method as a Cedar entity UID: Action::"<method_lowercase>"
func toCedarAction(method string) string {
	return fmt.Sprintf(`Action::"%s"`, strings.ToLower(method))
}

// toCedarResource formats a path as a Cedar entity UID: Resource::"<path>"
func toCedarResource(path string) string {
	return fmt.Sprintf(`Resource::"%s"`, path)
}

var body503 = []byte(`{"message":"authorization service unavailable"}`)
var body403 = []byte(`{"message":"forbidden"}`)

// exit503 terminates the request with 503 + Retry-After: 5.
// Used for PDP timeout, connection failure, and PDP-side 503.
// CRITICAL per ADR-006: PDP unavailability must NEVER produce 403.
func exit503(kong *pdk.PDK) {
	headers := map[string][]string{
		"Retry-After": {"5"},
	}
	kong.Response.Exit(503, body503, headers)
}

// Access is the Kong access phase handler for the plugin.
func (conf *Config) Access(kong *pdk.PDK) {
	// Resolve principal.
	principalID, err := getPrincipal(kong)
	if err != nil {
		// Should not happen -- fallback returns "anonymous" without error.
		_ = kong.Log.Err("cedar-pdp: failed to resolve principal: " + err.Error())
		exit503(kong)
		return
	}

	// Resolve method and path.
	method, err := kong.Request.GetMethod()
	if err != nil {
		_ = kong.Log.Err("cedar-pdp: failed to get HTTP method: " + err.Error())
		exit503(kong)
		return
	}

	path, err := kong.Request.GetPath()
	if err != nil {
		_ = kong.Log.Err("cedar-pdp: failed to get request path: " + err.Error())
		exit503(kong)
		return
	}

	// Build the PDP request payload.
	payload := pdpRequest{
		Principal: toCedarPrincipal(principalID),
		Action:    toCedarAction(method),
		Resource:  toCedarResource(path),
		Context:   map[string]any{},
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		_ = kong.Log.Err("cedar-pdp: failed to marshal request payload: " + err.Error())
		exit503(kong)
		return
	}

	// Build HTTP client with configured timeout.
	timeoutMs := conf.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = 3000
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond

	pdpEndpoint := conf.PdpUrl + "/v1/is_authorized"
	if conf.PdpUrl == "" {
		pdpEndpoint = "http://127.0.0.1:8180/v1/is_authorized"
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pdpEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		_ = kong.Log.Err("cedar-pdp: failed to build HTTP request: " + err.Error())
		exit503(kong)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := pdpClient.Do(req)

	// PDP timeout or connection error -> 503 + Retry-After (ADR-006).
	// CRITICAL: timeout must never produce 403.
	if err != nil {
		_ = kong.Log.Warn(fmt.Sprintf(
			"cedar-pdp: PDP request failed (%s) for principal=%s %s %s",
			err.Error(), principalID, method, path,
		))
		exit503(kong)
		return
	}
	defer resp.Body.Close()

	// PDP returned HTTP 503 (overloaded / backpressure) -> propagate 503 + Retry-After.
	if resp.StatusCode == http.StatusServiceUnavailable {
		_ = kong.Log.Warn(fmt.Sprintf(
			"cedar-pdp: PDP returned 503 for principal=%s %s %s",
			principalID, method, path,
		))
		exit503(kong)
		return
	}

	// Decode the response body.
	var pdpResp pdpResponse
	if err := json.NewDecoder(resp.Body).Decode(&pdpResp); err != nil {
		_ = kong.Log.Err(fmt.Sprintf(
			"cedar-pdp: failed to decode PDP response (status=%d): %s",
			resp.StatusCode, err.Error(),
		))
		exit503(kong)
		return
	}

	// Allow -> pass through, return without action.
	if pdpResp.Decision == "Allow" {
		_ = kong.Log.Debug(fmt.Sprintf(
			"cedar-pdp: Allow for principal=%s %s %s",
			principalID, method, path,
		))
		return
	}

	// Deny (or any unrecognised decision) -> 403.
	_ = kong.Log.Info(fmt.Sprintf(
		"cedar-pdp: Deny for principal=%s %s %s decision=%s",
		principalID, method, path, pdpResp.Decision,
	))
	kong.Response.Exit(403, body403, nil)
}

func main() {
	server.StartServer(New, Version, Priority)
}
