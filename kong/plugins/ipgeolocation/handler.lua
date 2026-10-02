-- Kong Gateway plugin: IP intelligence and security powered by
-- IPGeolocation.io MMDB databases.
--
-- Phases
--   configure  open/refresh databases off the request path (every worker)
--   rewrite    runs only for global instances (Kong has not routed yet):
--              strip spoofed headers, look up, set headers. Kong's router can
--              therefore match routes on X-IPGeo-* headers.
--   access     runs for every scope. Re-uses the rewrite result when the same
--              instance applies; otherwise (a Route or Service instance
--              overrides the global one) recomputes with that configuration.
--              Enforces the policy here, so Kong's normal precedence between
--              global, Service and Route configurations is preserved.
--
-- The client address is always kong.client.get_forwarded_ip(): the address
-- Kong's real-IP processing (trusted_ips, real_ip_header,
-- real_ip_recursive) established. The plugin never parses X-Forwarded-For
-- itself.

local plan_mod = require "kong.plugins.ipgeolocation.plan"
local registry = require "kong.plugins.ipgeolocation.registry"
local resolver = require "kong.plugins.ipgeolocation.resolver"
local headers = require "kong.plugins.ipgeolocation.headers"
local policy = require "kong.plugins.ipgeolocation.policy"
local iputil = require "kong.plugins.ipgeolocation.iputil"
local fields = require "kong.plugins.ipgeolocation.fields"

-- Public, read-only interface for other plugins (lower priority):
--   kong.ctx.shared.ipgeolocation = {
--     ip, found, private, exempt, fields = { <field> = value, ... },
--     blocked, dry_run, reason }
local CTX_KEY = "ipgeolocation"
-- Internal hand-off between the rewrite and access phases.
local STATE_KEY = "ipgeolocation.state"

local LOG_INTERVAL = 60
local last_failure_log = 0

local IPGeolocationHandler = {
  PRIORITY = 2450,   -- after bot-detection (2500), before cors and authentication
  VERSION = "0.1.0",
}

function IPGeolocationHandler:configure(configs)
  registry.sync(configs)
end

local function log_failure(failure)
  local now = ngx.now()
  if now - last_failure_log >= LOG_INTERVAL then
    last_failure_log = now
    kong.log.warn("IP intelligence unavailable: ", failure)
  end
end

local function enrich(conf, plan)
  headers.strip(plan)

  local ip_text = kong.client.get_forwarded_ip()
  local bytes, n, ip = iputil.parse(ip_text)
  local result = {
    ip = ip or ip_text,
    found = false,
    private = false,
    fields = {},
  }
  local state = {
    conf = conf,
    plugin_id = conf.__plugin_id,
    plan = plan,
    result = result,
    bytes = bytes,
    n = n,
    set_headers = {},
  }

  if not bytes then
    state.failure = "client address is not an IP address"
  elseif plan.allow_private and iputil.is_private(bytes, n) then
    result.private = true
  else
    local values, texts, found, failure = resolver.resolve(plan, bytes, n, registry.get)
    result.fields, result.found = values, found
    state.failure = failure
    state.set_headers = headers.apply(plan, values, texts, ip)
  end

  kong.ctx.shared[CTX_KEY] = result
  return state
end

local function serialize(plan, result)
  if plan.log_serialize then
    kong.log.set_serialize_value("ipgeolocation", {
      ip = result.ip,
      found = result.found,
      private = result.private,
      exempt = result.exempt,
      blocked = result.blocked,
      dry_run = result.dry_run,
      reason = result.reason,
      fields = result.fields,
    })
  end
end

local function enforce(state)
  local plan, result = state.plan, state.result

  if state.failure then
    log_failure(state.failure)
  end

  if result.private then
    return serialize(plan, result)
  end

  if plan.exempt and state.bytes and iputil.any_match(plan.exempt, state.bytes, state.n) then
    result.exempt = true
    return serialize(plan, result)
  end

  local reason
  if state.failure and not plan.fail_open then
    reason = "IP intelligence unavailable"
  else
    -- Failing open: a value the failure left unknown must not block either.
    reason = policy.evaluate(plan.policy, result.fields, state.failure ~= nil)
  end

  if not reason then
    return serialize(plan, result)
  end

  result.reason = reason
  if plan.dry_run then
    result.dry_run = true
    result.blocked = false
    kong.service.request.set_header(fields.DRY_RUN_HEADER, headers.sanitize(reason, 256))
    kong.log.notice("dry run, would block ", result.ip, ": ", reason)
    return serialize(plan, result)
  end

  result.blocked = true
  kong.log.info("blocked ", result.ip, ": ", reason)
  serialize(plan, result)
  return kong.response.error(plan.status, plan.message)
end

local function get_plan(conf)
  local plan, err = plan_mod.get(conf)
  if not plan then
    kong.log.err("invalid configuration: ", err)
  end
  return plan
end

local function plan_failure(conf)
  -- Configuration could not be compiled (should be impossible after schema
  -- validation). Still never pass spoofed headers through.
  headers.strip(nil)
  local p = plan_mod.opt(conf.policy, "table", {})
  if p.fail_open == false then
    return kong.response.error(plan_mod.opt(p.status_code, "number", 403),
                               plan_mod.opt(p.message, "string", "Access denied"))
  end
end

function IPGeolocationHandler:rewrite(conf)
  local plan = get_plan(conf)
  if not plan then
    headers.strip(nil)
    return
  end
  kong.ctx.shared[STATE_KEY] = enrich(conf, plan)
end

function IPGeolocationHandler:access(conf)
  local plan = get_plan(conf)
  if not plan then
    return plan_failure(conf)
  end

  local shared = kong.ctx.shared
  local state = shared[STATE_KEY]
  local same = state and (state.conf == conf
                          or (state.plugin_id ~= nil and state.plugin_id == conf.__plugin_id))
  if not same then
    if state then
      -- A more specific instance overrides the global one that ran in
      -- rewrite: drop what the global instance set, including custom names.
      headers.clear(state.set_headers)
    end
    state = enrich(conf, plan)
    shared[STATE_KEY] = state
  end

  return enforce(state)
end

return IPGeolocationHandler
