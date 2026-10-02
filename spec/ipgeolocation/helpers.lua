-- Shared helpers for the unit tests.
local fixtures = require "spec.ipgeolocation.fixtures"

local _M = {}

local counter = 0
function _M.tmpdir()
  counter = counter + 1
  local base = os.tmpname()
  os.remove(base)
  local dir = base .. "-ipgeo-" .. counter
  assert(os.execute("mkdir -p '" .. dir .. "'"))
  return dir
end

local built
function _M.fixtures()
  if not built then
    built = fixtures.build_all(_M.tmpdir())
  end
  return built
end

local function deep_merge(base, over)
  local out = {}
  for k, v in pairs(base) do
    out[k] = type(v) == "table" and deep_merge(v, {}) or v
  end
  for k, v in pairs(over or {}) do
    if type(v) == "table" and type(out[k]) == "table" and #v == 0 and next(v) ~= nil then
      out[k] = deep_merge(out[k], v)
    else
      out[k] = v
    end
  end
  return out
end
_M.deep_merge = deep_merge

-- A configuration as Kong produces it after applying schema defaults.
function _M.conf(over)
  return deep_merge({
    databases = {},
    database_refresh_interval = 0,
    headers = {
      preset = "minimal", custom = {}, boolean_format = "true_false",
      list_separator = ",", language = "en", max_value_length = 1024,
    },
    policy = {
      allowed_countries = {}, blocked_countries = {}, allowed_continents = {}, blocked_continents = {},
      allowed_asns = {}, blocked_asns = {},
      block_tor = false, block_vpn = false, block_proxy = false, block_relay = false,
      block_residential_proxy = false, block_anonymous = false, block_known_attacker = false,
      block_bot = false, block_known_good_bots = false, block_spam = false,
      block_cloud_provider = false, block_corporate_gateway = false,
      exempt_ips = {}, allow_private = true, allow_unknown = true, fail_open = true,
      dry_run = false, status_code = 403, message = "Access denied",
    },
    log_serialize = false,
  }, over)
end

return _M
