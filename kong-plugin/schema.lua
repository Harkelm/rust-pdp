-- schema.lua
-- Config schema for the cedar-pdp Kong plugin.
--
-- Fields:
--   pdp_url    URL of the Cedar PDP sidecar (default: http://127.0.0.1:8180)
--   timeout_ms HTTP client timeout in milliseconds (default: 3000)
--
-- NOTE: There is deliberately NO fail_open field. Fail-open is a P0 security
-- issue (ADR-006). If specific routes should bypass authorization, model that
-- in Cedar policy, not in plugin config.

local typedefs = require("kong.db.schema.typedefs")

return {
  name = "cedar-pdp",
  fields = {
    {
      config = {
        type   = "record",
        fields = {
          {
            pdp_url = {
              type     = "string",
              default  = "http://127.0.0.1:8180",
              required = true,
            },
          },
          {
            timeout_ms = {
              type     = "integer",
              default  = 3000,
              required = true,
              gt       = 0,
            },
          },
        },
      },
    },
  },
}
