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
	"sync"
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
	PdpUrl     string `json:"pdp_url"`
	TimeoutMs  int    `json:"timeout_ms"`
	CacheTtlMs int    `json:"cache_ttl_ms"`
}

// New returns a default Config used as the plugin factory.
func New() interface{} {
	return &Config{
		PdpUrl:     "http://127.0.0.1:8180",
		TimeoutMs:  3000,
		CacheTtlMs: 30000,
	}
}

// --- Decision cache (ADR-003 mandatory) ---

type cacheEntry struct {
	decision string
	expiry   time.Time
}

var (
	cacheMu sync.RWMutex
	cache   = make(map[string]cacheEntry)
)

// cacheKey builds a lookup key from the PARC triple.
func cacheKey(principal, action, resource string) string {
	return principal + "|" + action + "|" + resource
}

// cacheLookup returns the cached decision if present and not expired.
func cacheLookup(key string) (string, bool) {
	cacheMu.RLock()
	entry, ok := cache[key]
	cacheMu.RUnlock()
	if !ok || time.Now().After(entry.expiry) {
		return "", false
	}
	return entry.decision, true
}

// cacheStore saves a decision with the given TTL. Only Allow/Deny are cached;
// errors and transient failures must never be cached.
func cacheStore(key, decision string, ttl time.Duration) {
	cacheMu.Lock()
	cache[key] = cacheEntry{decision: decision, expiry: time.Now().Add(ttl)}
	cacheMu.Unlock()
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

// toCedarPrincipal formats an ID as a Cedar entity UID with ApiGateway namespace.
func toCedarPrincipal(id string) string {
	return fmt.Sprintf(`ApiGateway::User::"%s"`, id)
}

// methodToAction maps HTTP method to Cedar action name per the ApiGateway schema.
// Must match entities.rs method_to_action for consistency between legacy and claims paths.
func methodToAction(method string) string {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return "read"
	case "POST", "PUT", "PATCH":
		return "write"
	case "DELETE":
		return "delete"
	default:
		return "read"
	}
}

// toCedarAction formats an HTTP method as a Cedar entity UID with ApiGateway namespace.
func toCedarAction(method string) string {
	return fmt.Sprintf(`ApiGateway::Action::"%s"`, methodToAction(method))
}

// toCedarResource formats a path as a Cedar entity UID with ApiGateway namespace.
func toCedarResource(path string) string {
	return fmt.Sprintf(`ApiGateway::ApiResource::"%s"`, path)
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

	// Cache lookup (ADR-003 mandatory plugin-side decision cache).
	principal := toCedarPrincipal(principalID)
	action := toCedarAction(method)
	resource := toCedarResource(path)
	key := cacheKey(principal, action, resource)

	if decision, ok := cacheLookup(key); ok {
		if decision == "Allow" {
			_ = kong.Log.Debug(fmt.Sprintf(
				"cedar-pdp: cache hit Allow for principal=%s %s %s",
				principalID, method, path,
			))
			return
		}
		_ = kong.Log.Info(fmt.Sprintf(
			"cedar-pdp: cache hit Deny for principal=%s %s %s",
			principalID, method, path,
		))
		kong.Response.Exit(403, body403, nil)
		return
	}

	// Build the PDP request payload.
	payload := pdpRequest{
		Principal: principal,
		Action:    action,
		Resource:  resource,
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

	// Any non-200 PDP response is a PDP error -> 503 + Retry-After (ADR-006).
	// CRITICAL: non-200 must NEVER produce 403 -- that would deny legitimate
	// requests due to PDP bugs, bad requests, or internal errors.
	if resp.StatusCode != http.StatusOK {
		_ = kong.Log.Warn(fmt.Sprintf(
			"cedar-pdp: PDP returned %d for principal=%s %s %s",
			resp.StatusCode, principalID, method, path,
		))
		exit503(kong)
		return
	}

	// Decode the response body (200 OK only).
	var pdpResp pdpResponse
	if err := json.NewDecoder(resp.Body).Decode(&pdpResp); err != nil {
		_ = kong.Log.Err(fmt.Sprintf(
			"cedar-pdp: failed to decode PDP response (status=%d): %s",
			resp.StatusCode, err.Error(),
		))
		exit503(kong)
		return
	}

	// Compute cache TTL from config.
	cacheTtlMs := conf.CacheTtlMs
	if cacheTtlMs <= 0 {
		cacheTtlMs = 30000
	}
	cacheTtl := time.Duration(cacheTtlMs) * time.Millisecond

	// Allow -> cache and pass through.
	if pdpResp.Decision == "Allow" {
		cacheStore(key, "Allow", cacheTtl)
		_ = kong.Log.Debug(fmt.Sprintf(
			"cedar-pdp: Allow for principal=%s %s %s",
			principalID, method, path,
		))
		return
	}

	// Deny (or any unrecognised decision) -> cache and 403.
	cacheStore(key, pdpResp.Decision, cacheTtl)
	_ = kong.Log.Info(fmt.Sprintf(
		"cedar-pdp: Deny for principal=%s %s %s decision=%s",
		principalID, method, path, pdpResp.Decision,
	))
	kong.Response.Exit(403, body403, nil)
}

func main() {
	server.StartServer(New, Version, Priority)
}
