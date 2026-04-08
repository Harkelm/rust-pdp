-- handler.lua
-- Kong plugin: Cedar PDP authorization callout
--
-- Phase: access
-- Priority: 925 (after auth plugins at 950, before rate limiting)
--
-- Extracts principal + request context, POSTs to Cedar PDP sidecar,
-- enforces the decision per ADR-006 (no fail-open, 503+Retry-After
-- for PDP unavailability).

local http = require("resty.http")
local cjson = require("cjson.safe")

local CedarAuthHandler = {
  PRIORITY = 925,
  VERSION = "0.1.0",
}

-- Extract the principal identifier from the Kong request context.
-- Resolution order:
--   1. Kong consumer (set by authentication plugins upstream)
--   2. X-Consumer-ID request header
--   3. Literal "anonymous"
local function get_principal()
  local consumer = kong.client.get_consumer()
  if consumer and consumer.id then
    return consumer.id
  end

  local header_id = kong.request.get_header("X-Consumer-ID")
  if header_id and header_id ~= "" then
    return header_id
  end

  return "anonymous"
end

-- Build a Cedar entity UID string from a raw identifier.
-- Format: User::"<id>"
local function to_cedar_principal(id)
  return string.format('User::"%s"', id)
end

-- Build the Cedar action UID from the HTTP method.
-- HTTP method is lowercased: GET -> Action::"get"
local function to_cedar_action(method)
  return string.format('Action::"%s"', string.lower(method))
end

-- Build the Cedar resource UID from the request path.
-- Format: Resource::"<path>"
local function to_cedar_resource(path)
  return string.format('Resource::"%s"', path)
end

function CedarAuthHandler:access(conf)
  -- Build the authorization request payload.
  local principal_id = get_principal()
  local method       = kong.request.get_method()
  local path         = kong.request.get_path()

  local payload = {
    principal = to_cedar_principal(principal_id),
    action    = to_cedar_action(method),
    resource  = to_cedar_resource(path),
    context   = {},
  }

  local body, encode_err = cjson.encode(payload)
  if encode_err then
    kong.log.err("cedar-pdp: failed to encode request payload: ", encode_err)
    return kong.response.exit(503, { message = "authorization service unavailable" },
      { ["Retry-After"] = "5" })
  end

  -- Send the authorization request to the PDP sidecar.
  local httpc = http.new()
  httpc:set_timeout(conf.timeout_ms)

  local pdp_url = conf.pdp_url .. "/v1/is_authorized"

  local res, req_err = httpc:request_uri(pdp_url, {
    method  = "POST",
    body    = body,
    headers = {
      ["Content-Type"] = "application/json",
      ["Accept"]       = "application/json",
    },
  })

  -- PDP timeout or connection error -> 503 + Retry-After (ADR-006).
  -- CRITICAL: timeout must never produce 403.
  if req_err then
    kong.log.warn("cedar-pdp: PDP request failed (", req_err, ") for principal=",
      principal_id, " ", method, " ", path)
    return kong.response.exit(503, { message = "authorization service unavailable" },
      { ["Retry-After"] = "5" })
  end

  -- PDP returned HTTP 503 (overloaded / backpressure) -> propagate 503 + Retry-After.
  if res.status == 503 then
    kong.log.warn("cedar-pdp: PDP returned 503 for principal=", principal_id,
      " ", method, " ", path)
    return kong.response.exit(503, { message = "authorization service unavailable" },
      { ["Retry-After"] = "5" })
  end

  -- Parse the response body.
  local response, decode_err = cjson.decode(res.body)
  if decode_err or not response then
    kong.log.err("cedar-pdp: failed to decode PDP response (status=", res.status,
      "): ", decode_err)
    return kong.response.exit(503, { message = "authorization service unavailable" },
      { ["Retry-After"] = "5" })
  end

  local decision = response.decision

  -- Allow -> pass through, do nothing.
  if decision == "Allow" then
    kong.log.debug("cedar-pdp: Allow for principal=", principal_id, " ", method, " ", path)
    return
  end

  -- Deny (or any unrecognised decision) -> 403.
  kong.log.info("cedar-pdp: Deny for principal=", principal_id, " ", method, " ", path,
    " decision=", tostring(decision))
  return kong.response.exit(403, { message = "forbidden" })
end

return CedarAuthHandler
