-- Minimal stand-ins for the Kong PDK and ngx API used by the plugin, so the
-- handler can be exercised without a running gateway. Headers sent upstream
-- are modelled the way nginx exposes them: lower-cased names, case-insensitive
-- set/clear, and get_headers() reflecting earlier modifications.
local _M = {}

local saved

function _M.install(opts)
  opts = opts or {}
  saved = { kong = rawget(_G, "kong"), ngx = rawget(_G, "ngx") }
  local req = {
    ip = opts.ip,
    upstream = {},
    logs = {},
    serialized = {},
    now = opts.now or 1000,
    get_headers_calls = 0,
  }
  for name, value in pairs(opts.headers or {}) do
    req.upstream[name:lower()] = value
  end

  local real = saved.ngx
  local ngx_mock = setmetatable({}, { __index = real })
  ngx_mock.req = setmetatable({
    get_headers = function(max)
      req.get_headers_calls = req.get_headers_calls + 1
      assert(max == 0, "request headers must be enumerated without a limit")
      local copy = {}
      for k, v in pairs(req.upstream) do copy[k] = v end
      return copy
    end,
  }, { __index = real and real.req })
  ngx_mock.now = function() return req.now end
  ngx_mock.timer = { every = function() return true end }
  ngx_mock.log = function(...) req.logs[#req.logs + 1] = { "ngx", ... } end
  ngx_mock.NOTICE, ngx_mock.WARN, ngx_mock.ERR, ngx_mock.INFO, ngx_mock.DEBUG = 6, 5, 4, 7, 8

  local function logger(level)
    return function(...)
      local parts = {}
      for i = 1, select("#", ...) do parts[#parts + 1] = tostring((select(i, ...))) end
      req.logs[#req.logs + 1] = { level, table.concat(parts) }
    end
  end

  local kong_mock = {
    client = { get_forwarded_ip = function() return req.ip end },
    service = { request = {
      set_header = function(name, value)
        assert(type(value) == "string", "header values must be strings")
        assert(not value:find("[\r\n]"), "header value contains CR/LF")
        req.upstream[name:lower()] = value
      end,
      clear_header = function(name)
        req.upstream[name:lower()] = nil
      end,
    } },
    response = {
      error = function(status, message)
        req.exit = { status = status, message = message }
      end,
    },
    ctx = { shared = {}, plugin = {} },
    log = {
      err = logger("err"), warn = logger("warn"), notice = logger("notice"),
      info = logger("info"), debug = logger("debug"),
      set_serialize_value = function(key, value) req.serialized[key] = value end,
    },
  }

  rawset(_G, "ngx", ngx_mock)
  rawset(_G, "kong", kong_mock)
  return req
end

function _M.uninstall()
  if saved then
    rawset(_G, "kong", saved.kong)
    rawset(_G, "ngx", saved.ngx)
    saved = nil
  end
end

-- Returns log lines at `level` containing `text`.
function _M.logged(req, level, text)
  local hits = {}
  for _, l in ipairs(req.logs) do
    if l[1] == level and (not text or (l[2] or ""):find(text, 1, true)) then
      hits[#hits + 1] = l[2]
    end
  end
  return hits
end

return _M
