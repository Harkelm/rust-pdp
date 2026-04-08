-- spec/handler_spec.lua
-- Unit tests for the cedar-pdp Kong plugin handler.
--
-- Test framework: busted (https://olivinelabs.com/busted/)
-- Run with: busted spec/handler_spec.lua
--
-- These tests mock the Kong PDK and resty.http to exercise all ADR-006
-- response branches without requiring a live Kong or PDP instance.

local busted = require("busted")
local describe = busted.describe
local it = busted.it
local before_each = busted.before_each
local assert = require("luassert")
local spy = require("luassert.spy")
local stub = require("luassert.stub")

-- ---------------------------------------------------------------------------
-- Kong PDK mock
-- ---------------------------------------------------------------------------

local kong_mock = {
  request = {},
  response = {},
  client = {},
  log = {
    debug = function(...) end,
    info  = function(...) end,
    warn  = function(...) end,
    err   = function(...) end,
  },
}

-- Tracks the last exit() call so tests can inspect it.
local last_exit = {}

function kong_mock.response.exit(status, body, headers)
  last_exit = { status = status, body = body, headers = headers or {} }
end

-- Expose as global `kong` so handler.lua picks it up.
_G.kong = kong_mock

-- ---------------------------------------------------------------------------
-- resty.http mock
-- ---------------------------------------------------------------------------

-- We replace require("resty.http") via package.preload before loading the
-- handler. Each test configures `http_response` to control what the mock
-- returns.

local http_response = {}   -- set per test: { status, body } or { err = "..." }
local last_request  = {}   -- captures what was POSTed to the PDP

local http_mock = {}
http_mock.__index = http_mock

function http_mock:set_timeout(_ms) end

function http_mock:request_uri(url, opts)
  last_request = { url = url, opts = opts }
  if http_response.err then
    return nil, http_response.err
  end
  return { status = http_response.status, body = http_response.body }, nil
end

package.preload["resty.http"] = function()
  return { new = function() return setmetatable({}, http_mock) end }
end

-- ---------------------------------------------------------------------------
-- cjson mock (use stdlib json via cjson.safe shim if cjson not installed)
-- ---------------------------------------------------------------------------

local ok_cjson, cjson_real = pcall(require, "cjson.safe")
if not ok_cjson then
  -- Minimal shim so the test file can load without luacjson installed.
  -- Real Kong environments have cjson; this shim lets tests run standalone.
  local json = {}
  local function encode_value(v)
    local t = type(v)
    if t == "string"  then return string.format("%q", v) end
    if t == "number"  then return tostring(v) end
    if t == "boolean" then return tostring(v) end
    if t == "nil"     then return "null" end
    if t == "table" then
      -- Check if array
      local is_array = #v > 0
      if is_array then
        local parts = {}
        for _, val in ipairs(v) do parts[#parts+1] = encode_value(val) end
        return "[" .. table.concat(parts, ",") .. "]"
      else
        local parts = {}
        for k, val in pairs(v) do
          parts[#parts+1] = string.format("%q", k) .. ":" .. encode_value(val)
        end
        return "{" .. table.concat(parts, ",") .. "}"
      end
    end
    error("unsupported type: " .. t)
  end
  function json.encode(t) local ok, r = pcall(encode_value, t); if ok then return r, nil else return nil, r end end
  function json.decode(s)
    -- Minimal decoder: only handles the PDP response shape we care about.
    local decision = s:match('"decision"%s*:%s*"(%w+)"')
    if decision then return { decision = decision }, nil end
    return nil, "decode failed"
  end
  package.preload["cjson.safe"] = function() return json end
end

-- ---------------------------------------------------------------------------
-- Load the handler under test
-- ---------------------------------------------------------------------------

local handler = require("handler")

-- Default plugin config matching schema defaults.
local default_conf = {
  pdp_url    = "http://127.0.0.1:8180",
  timeout_ms = 3000,
}

-- ---------------------------------------------------------------------------
-- Helper: reset state before each test
-- ---------------------------------------------------------------------------

local function reset()
  last_exit    = {}
  last_request = {}
  http_response = {}
  -- Reset Kong PDK request mock to sane defaults.
  kong_mock.request.get_method  = function() return "GET" end
  kong_mock.request.get_path    = function() return "/api/v1/resource" end
  kong_mock.request.get_header  = function(_) return nil end
  kong_mock.client.get_consumer = function() return nil end
end

-- ---------------------------------------------------------------------------
-- Test suite
-- ---------------------------------------------------------------------------

describe("cedar-pdp handler", function()

  before_each(reset)

  -- -------------------------------------------------------------------------
  -- 1. Request context extraction
  -- -------------------------------------------------------------------------

  describe("request context extraction", function()

    it("uses Kong consumer ID when consumer is present", function()
      kong_mock.client.get_consumer = function()
        return { id = "consumer-uuid-1234" }
      end
      http_response = { status = 200, body = '{"decision":"Allow"}' }

      handler:access(default_conf)

      local cjson = require("cjson.safe")
      local body = cjson.decode(last_request.opts.body)
      assert.equals('ApiGateway::User::"consumer-uuid-1234"', body.principal)
    end)

    it("ignores X-Consumer-ID header (BL-165: spoofable)", function()
      kong_mock.client.get_consumer = function() return nil end
      kong_mock.request.get_header = function(name)
        if name == "X-Consumer-ID" then return "header-consumer-id" end
        return nil
      end
      http_response = { status = 200, body = '{"decision":"Allow"}' }

      handler:access(default_conf)

      local cjson = require("cjson.safe")
      local body = cjson.decode(last_request.opts.body)
      -- Must NOT use header value; must fall through to anonymous.
      assert.equals('ApiGateway::User::"anonymous"', body.principal)
    end)

    it("falls back to anonymous when no consumer", function()
      kong_mock.client.get_consumer = function() return nil end
      kong_mock.request.get_header  = function(_) return nil end
      http_response = { status = 200, body = '{"decision":"Allow"}' }

      handler:access(default_conf)

      local cjson = require("cjson.safe")
      local body = cjson.decode(last_request.opts.body)
      assert.equals('ApiGateway::User::"anonymous"', body.principal)
    end)

    it("maps HTTP method to Cedar action name", function()
      kong_mock.request.get_method = function() return "POST" end
      http_response = { status = 200, body = '{"decision":"Allow"}' }

      handler:access(default_conf)

      local cjson = require("cjson.safe")
      local body = cjson.decode(last_request.opts.body)
      assert.equals('ApiGateway::Action::"write"', body.action)
    end)

    it("uses the request path as the Cedar resource", function()
      kong_mock.request.get_path = function() return "/api/v1/users" end
      http_response = { status = 200, body = '{"decision":"Allow"}' }

      handler:access(default_conf)

      local cjson = require("cjson.safe")
      local body = cjson.decode(last_request.opts.body)
      assert.equals('ApiGateway::ApiResource::"/api/v1/users"', body.resource)
    end)

    it("rejects unknown HTTP methods with 403 (BL-164)", function()
      kong_mock.request.get_method = function() return "TRACE" end

      handler:access(default_conf)

      assert.equals(403, last_exit.status)
    end)

    it("posts to the correct PDP endpoint", function()
      http_response = { status = 200, body = '{"decision":"Allow"}' }

      handler:access(default_conf)

      assert.equals("http://127.0.0.1:8180/v1/is_authorized", last_request.url)
    end)

  end)

  -- -------------------------------------------------------------------------
  -- 2. PDP Allow -> pass through
  -- -------------------------------------------------------------------------

  describe("PDP Allow response", function()

    it("does not call kong.response.exit when decision is Allow", function()
      http_response = { status = 200, body = '{"decision":"Allow","diagnostics":{}}' }

      handler:access(default_conf)

      assert.is_nil(last_exit.status)
    end)

  end)

  -- -------------------------------------------------------------------------
  -- 3. PDP Deny -> 403
  -- -------------------------------------------------------------------------

  describe("PDP Deny response", function()

    it("returns 403 when decision is Deny", function()
      http_response = { status = 200, body = '{"decision":"Deny","diagnostics":{}}' }

      handler:access(default_conf)

      assert.equals(403, last_exit.status)
    end)

    it("returns 403 for unknown decision values (fail-closed)", function()
      http_response = { status = 200, body = '{"decision":"Unknown"}' }

      handler:access(default_conf)

      assert.equals(403, last_exit.status)
    end)

    it("does NOT include Retry-After on 403", function()
      http_response = { status = 200, body = '{"decision":"Deny"}' }

      handler:access(default_conf)

      assert.equals(403, last_exit.status)
      assert.is_nil(last_exit.headers["Retry-After"])
    end)

  end)

  -- -------------------------------------------------------------------------
  -- 4. PDP HTTP 503 -> 503 + Retry-After
  -- -------------------------------------------------------------------------

  describe("PDP HTTP 503 response", function()

    it("returns 503 when PDP responds with HTTP 503", function()
      http_response = { status = 503, body = "" }

      handler:access(default_conf)

      assert.equals(503, last_exit.status)
    end)

    it("includes Retry-After header on PDP 503", function()
      http_response = { status = 503, body = "" }

      handler:access(default_conf)

      assert.equals("5", last_exit.headers["Retry-After"])
    end)

  end)

  -- -------------------------------------------------------------------------
  -- 5. PDP timeout (request error) -> 503 + Retry-After
  --    CRITICAL: must NOT produce 403
  -- -------------------------------------------------------------------------

  describe("PDP timeout / connection error", function()

    it("returns 503 on request error (not 403)", function()
      http_response = { err = "timeout" }

      handler:access(default_conf)

      assert.equals(503, last_exit.status)
      assert.not_equal(403, last_exit.status)
    end)

    it("includes Retry-After header on timeout", function()
      http_response = { err = "timeout" }

      handler:access(default_conf)

      assert.equals("5", last_exit.headers["Retry-After"])
    end)

    it("returns 503 on connection refused (not 403)", function()
      http_response = { err = "connection refused" }

      handler:access(default_conf)

      assert.equals(503, last_exit.status)
      assert.not_equal(403, last_exit.status)
    end)

  end)

  -- -------------------------------------------------------------------------
  -- 6. Schema: no fail_open field
  -- -------------------------------------------------------------------------

  describe("schema", function()

    it("has no fail_open field", function()
      local schema = require("schema")
      -- Walk the config fields and assert fail_open is absent.
      local config_fields = schema.fields[1].config.fields
      for _, field in ipairs(config_fields) do
        for k, _ in pairs(field) do
          assert.not_equal("fail_open", k,
            "fail_open must not exist in schema (ADR-006 P0 security requirement)")
        end
      end
    end)

    it("has pdp_url with correct default", function()
      local schema = require("schema")
      local config_fields = schema.fields[1].config.fields
      local found = false
      for _, field in ipairs(config_fields) do
        if field.pdp_url then
          found = true
          assert.equals("http://127.0.0.1:8180", field.pdp_url.default)
        end
      end
      assert.is_true(found, "pdp_url field must be present in schema")
    end)

    it("has timeout_ms with correct default", function()
      local schema = require("schema")
      local config_fields = schema.fields[1].config.fields
      local found = false
      for _, field in ipairs(config_fields) do
        if field.timeout_ms then
          found = true
          assert.equals(3000, field.timeout_ms.default)
        end
      end
      assert.is_true(found, "timeout_ms field must be present in schema")
    end)

  end)

end)
