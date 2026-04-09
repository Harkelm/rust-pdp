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

-- Decision cache (ADR-003 mandatory plugin-side decision cache).
-- Per-worker in-memory cache with TTL expiry.
-- Key: principal|action|resource|epoch (epoch from X-Policy-Epoch header).
-- Only Allow/Deny decisions are cached; errors/timeouts are never cached.
local decision_cache = {}

-- Current policy epoch from PDP, used for cache key versioning (RT-26 P1 #8).
-- Updated from each PDP response. When policies reload, epoch changes and
-- stale cached decisions naturally miss.
local current_policy_epoch = ""

local function cache_key(principal, action, resource)
  return principal .. "|" .. action .. "|" .. resource .. "|" .. current_policy_epoch
end

local function cache_lookup(key)
  local entry = decision_cache[key]
  if not entry then
    return nil
  end
  if ngx.now() > entry.expiry then
    decision_cache[key] = nil
    return nil
  end
  return entry.decision
end

-- Apply +/-20% jitter to TTL to prevent cache stampede on simultaneous
-- expiry (RT-26 P1 #9). Without jitter, all entries created in the same
-- window expire simultaneously, causing a burst of PDP requests.
local function jittered_ttl(ttl_seconds)
  return ttl_seconds * (0.8 + math.random() * 0.4)
end

local function cache_store(key, decision, ttl_seconds)
  decision_cache[key] = {
    decision = decision,
    expiry = ngx.now() + jittered_ttl(ttl_seconds),
  }
end

-- Extract the principal identifier from Kong's authenticated consumer.
-- Only kong.client.get_consumer() is trusted (set by auth plugins).
-- X-Consumer-ID header is NOT used -- it is client-supplied and spoofable (BL-165).
local function get_principal()
  local consumer = kong.client.get_consumer()
  if consumer and consumer.id then
    return consumer.id
  end

  return "anonymous"
end

-- Build a Cedar entity UID string with ApiGateway namespace.
local function to_cedar_principal(id)
  return string.format('ApiGateway::User::"%s"', id)
end

-- Map HTTP method to Cedar action name per the ApiGateway schema.
-- Must match entities.rs method_to_action for consistency between legacy and claims paths.
local method_action_map = {
  GET     = "read",
  HEAD    = "read",
  OPTIONS = "read",
  POST    = "write",
  PUT     = "write",
  PATCH   = "write",
  DELETE  = "delete",
}

local function method_to_action(method)
  return method_action_map[string.upper(method)]
end

-- Build the Cedar action UID with ApiGateway namespace.
local function to_cedar_action(method)
  return string.format('ApiGateway::Action::"%s"', method_to_action(method))
end

-- Build the Cedar resource UID with ApiGateway namespace.
local function to_cedar_resource(path)
  return string.format('ApiGateway::ApiResource::"%s"', path)
end

function CedarAuthHandler:access(conf)
  -- Build the authorization request payload.
  local principal_id = get_principal()
  local method       = kong.request.get_method()
  local path         = kong.request.get_path()

  -- Reject unknown HTTP methods (BL-164). Unknown methods must not default
  -- to "read" -- that would allow TRACE, PURGE, etc. through read policies.
  if not method_to_action(method) then
    kong.log.warn("cedar-pdp: unknown HTTP method ", method, " denied for principal=",
      principal_id, " ", path)
    return kong.response.exit(403, { message = "forbidden" })
  end

  local principal = to_cedar_principal(principal_id)
  local action    = to_cedar_action(method)
  local resource  = to_cedar_resource(path)

  -- Cache lookup (ADR-003 mandatory plugin-side decision cache).
  local key = cache_key(principal, action, resource)
  local cached = cache_lookup(key)
  if cached then
    if cached == "Allow" then
      kong.log.debug("cedar-pdp: cache hit Allow for principal=", principal_id,
        " ", method, " ", path)
      return
    end
    kong.log.info("cedar-pdp: cache hit Deny for principal=", principal_id,
      " ", method, " ", path)
    return kong.response.exit(403, { message = "forbidden" })
  end

  local payload = {
    principal = principal,
    action    = action,
    resource  = resource,
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

  -- Any non-200 PDP response is a PDP error -> 503 + Retry-After (ADR-006).
  -- CRITICAL: non-200 must NEVER produce 403 -- that would deny legitimate
  -- requests due to PDP bugs, bad requests, or internal errors.
  if res.status ~= 200 then
    kong.log.warn("cedar-pdp: PDP returned ", res.status, " for principal=",
      principal_id, " ", method, " ", path)
    return kong.response.exit(503, { message = "authorization service unavailable" },
      { ["Retry-After"] = "5" })
  end

  -- Parse the response body (200 OK only).
  local response, decode_err = cjson.decode(res.body)
  if decode_err or not response then
    kong.log.err("cedar-pdp: failed to decode PDP response (status=", res.status,
      "): ", decode_err)
    return kong.response.exit(503, { message = "authorization service unavailable" },
      { ["Retry-After"] = "5" })
  end

  -- Update policy epoch from PDP response for cache key versioning (RT-26 P1 #8).
  local new_epoch = res.headers and res.headers["X-Policy-Epoch"]
  if new_epoch and new_epoch ~= "" then
    current_policy_epoch = new_epoch
  end

  -- Rebuild cache key with updated epoch (may differ from lookup key if
  -- policies were reloaded between lookup and PDP call).
  key = cache_key(principal, action, resource)

  local decision = response.decision
  local cache_ttl = (conf.cache_ttl_ms or 30000) / 1000

  -- Allow -> cache and pass through.
  if decision == "Allow" then
    cache_store(key, "Allow", cache_ttl)
    kong.log.debug("cedar-pdp: Allow for principal=", principal_id, " ", method, " ", path)
    return
  end

  -- Deny (or any unrecognised decision) -> cache and 403.
  cache_store(key, decision, cache_ttl)
  kong.log.info("cedar-pdp: Deny for principal=", principal_id, " ", method, " ", path,
    " decision=", tostring(decision))
  return kong.response.exit(403, { message = "forbidden" })
end

return CedarAuthHandler
